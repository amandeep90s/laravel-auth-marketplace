<?php

use App\Http\Middleware\AlwaysAcceptJson;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->append(AlwaysAcceptJson::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {

        /**
         * Helper function to create a JSON response
         */
        $json = function (string $message, int $status, array $extra = []) {
            return response()->json(array_merge(['message' => $message], $extra), $status);
        };

        $exceptions->render(function (NotFoundHttpException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                return $json('Resource not found', Response::HTTP_NOT_FOUND);
            }
        });

        $exceptions->render(function (AuthenticationException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                return $json('Unauthenticated or token invalid/expired.', Response::HTTP_UNAUTHORIZED, [
                    'error' => $e->getMessage()
                ]);
            }
        });

        $exceptions->render(function (AuthorizationException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                return $json('This action is unauthorized.', Response::HTTP_FORBIDDEN, [
                    'error' => $e->getMessage()
                ]);
            }
        });

        $exceptions->render(function (MethodNotAllowedHttpException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                return $json('Method not allowed for this route.', Response::HTTP_METHOD_NOT_ALLOWED);
            }
        });

        $exceptions->render(function (ValidationException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                return $json('The given data was invalid.', Response::HTTP_UNPROCESSABLE_ENTITY, [
                    'errors' => $e->errors()
                ]);
            }
        });

        $exceptions->render(function (HttpException $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                $message = $e->getMessage() ?: Response::$statusTexts[$e->getStatusCode()] ?? 'HTTP error';
                return $json($message, $e->getStatusCode());
            }
        });

        $exceptions->render(function (Throwable $e, Request $request) use ($json) {
            if ($request->is('api/*')) {
                $debug = config('app.debug');

                return $json(
                    $debug ? $e->getMessage() : 'An unexpected error occurred.',
                    Response::HTTP_INTERNAL_SERVER_ERROR,
                    $debug ? [
                        'exception' => get_class($e),
                        'file' => $e->getFile(),
                        'line' => $e->getLine(),
                        'trace' => explode("\n", $e->getTraceAsString()),
                    ] : []
                );
            }
        });
    })->create();
