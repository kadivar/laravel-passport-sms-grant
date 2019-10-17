<?php

namespace Kadivar\Passport\Sms;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Bridge\User;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class SmsRequestGrant
 *
 * @author Mohammadreza Kadivar <me.kadivar@gmail.com>
 */
class SmsRequestGrant extends AbstractGrant
{
    /**
     * @param UserRepositoryInterface $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    )
    {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    )
    {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateUser($request);
        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());
        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);
        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);
        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'sms';
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return UserEntityInterface
     * @throws OAuthServerException
     */
    protected function validateUser(ServerRequestInterface $request)
    {
        $laravelRequest = new Request($request->getParsedBody());
        $user = $this->getUserEntityByRequest($laravelRequest);
        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidCredentials();
        }
        return $user;
    }

    /**
     * Retrieve user by request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Laravel\Passport\Bridge\User|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function getUserEntityByRequest(Request $request)
    {
        if (is_null($model = config('auth.providers.users.model'))) {
            throw OAuthServerException::serverError('Unable to determine user model from configuration.');
        }
        if (method_exists($model, 'getUserByMobile')) {
            $user_model = (new $model);
            try {
                Validator::make($request->all(), [
                    'mobile' => [
                        'required',
                        'min:11',
                        'max:11'
                    ],
                    'verify_code' => [
                        'required',
                        'max:6',
                        function ($attribute, $value, $fail) use ($user_model, $request) {
                            $user = $user_model->getUserByMobile($request->mobile);
                            $current_token = $user->sms_token;
                            if ((string)$current_token != (string)$value) {
                                return $fail($attribute.' is invalid.');
                            }
                        },
                    ]
                ])->validate();
            } catch (\Exception $e) {
                throw OAuthServerException::accessDenied($e->getMessage());
            }
            $user = $user_model->getUserByMobile($request->mobile);
        } else {
            throw OAuthServerException::serverError('Unable to find getUserByMobile method on user model.');
        }
        return ($user) ? new User($user->id) : null;
    }
}
