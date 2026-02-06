// --------------------------------------------------------------------------
// <copyright file="Result.cs" company="Phoenix Security">
//     Copyright © 2026 Phoenix Security. All rights reserved.
//     Enterprise Result Pattern Implementation
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Common;

/// <summary>
/// Represents the result of an operation that can succeed or fail.
/// Implements the Result pattern for consistent error handling.
/// </summary>
/// <typeparam name="T">The type of the value on success.</typeparam>
public sealed class Result<T>
{
    private readonly T? _value;
    private readonly Error? _error;

    private Result(T value)
    {
        IsSuccess = true;
        _value = value;
        _error = null;
    }

    private Result(Error error)
    {
        IsSuccess = false;
        _value = default;
        _error = error;
    }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets a value indicating whether the operation failed.
    /// </summary>
    public bool IsFailure => !IsSuccess;

    /// <summary>
    /// Gets the value if the operation succeeded.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing value on a failed result.</exception>
    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException($"Cannot access value of a failed result. Error: {_error}");

    /// <summary>
    /// Gets the error if the operation failed.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when accessing error on a successful result.</exception>
    public Error Error => IsFailure
        ? _error!
        : throw new InvalidOperationException("Cannot access error of a successful result.");

    /// <summary>
    /// Creates a successful result with the specified value.
    /// </summary>
    public static Result<T> Success(T value) => new(value);

    /// <summary>
    /// Creates a failed result with the specified error.
    /// </summary>
    public static Result<T> Failure(Error error) => new(error);

    /// <summary>
    /// Creates a failed result with the specified error code and message.
    /// </summary>
    public static Result<T> Failure(string code, string message) => new(new Error(code, message));

    /// <summary>
    /// Implicitly converts a value to a successful result.
    /// </summary>
    public static implicit operator Result<T>(T value) => Success(value);

    /// <summary>
    /// Implicitly converts an error to a failed result.
    /// </summary>
    public static implicit operator Result<T>(Error error) => Failure(error);

    /// <summary>
    /// Maps the value to a new result if successful.
    /// </summary>
    public Result<TNew> Map<TNew>(Func<T, TNew> mapper) =>
        IsSuccess ? Result<TNew>.Success(mapper(_value!)) : Result<TNew>.Failure(_error!);

    /// <summary>
    /// Binds to another result-returning operation if successful.
    /// </summary>
    public Result<TNew> Bind<TNew>(Func<T, Result<TNew>> binder) =>
        IsSuccess ? binder(_value!) : Result<TNew>.Failure(_error!);

    /// <summary>
    /// Matches the result to one of two functions based on success or failure.
    /// </summary>
    public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<Error, TResult> onFailure) =>
        IsSuccess ? onSuccess(_value!) : onFailure(_error!);

    /// <summary>
    /// Gets the value or a default if the operation failed.
    /// </summary>
    public T GetValueOrDefault(T defaultValue = default) =>
        IsSuccess ? _value : defaultValue;

    public override string ToString() =>
        IsSuccess ? $"Success({_value})" : $"Failure({_error})";
}

/// <summary>
/// Represents the result of an operation that can succeed or fail without returning a value.
/// </summary>
public sealed class Result
{
    private readonly Error? _error;

    private Result(bool isSuccess, Error? error)
    {
        IsSuccess = isSuccess;
        _error = error;
    }

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;

    public Error Error => IsFailure
        ? _error!
        : throw new InvalidOperationException("Cannot access error of a successful result.");

    public static Result Success() => new(true, null);
    public static Result Failure(Error error) => new(false, error);
    public static Result Failure(string code, string message) => new(false, new Error(code, message));

    public static implicit operator Result(Error error) => Failure(error);

    public Result<T> Map<T>(Func<T> mapper) =>
        IsSuccess ? Result<T>.Success(mapper()) : Result<T>.Failure(_error!);

    public TResult Match<TResult>(Func<TResult> onSuccess, Func<Error, TResult> onFailure) =>
        IsSuccess ? onSuccess() : onFailure(_error!);
}

/// <summary>
/// Represents an error with a code and message.
/// </summary>
/// <param name="Code">The error code for programmatic handling.</param>
/// <param name="Message">The human-readable error message.</param>
public record Error(string Code, string Message)
{
    /// <summary>
    /// No error - represents success.
    /// </summary>
    public static readonly Error None = new(string.Empty, string.Empty);

    /// <summary>
    /// A null value was provided where it wasn't allowed.
    /// </summary>
    public static readonly Error NullValue = new("Error.NullValue", "A null value was provided.");

    /// <summary>
    /// Creates a validation error.
    /// </summary>
    public static Error Validation(string message) => new("Error.Validation", message);

    /// <summary>
    /// Creates a not found error.
    /// </summary>
    public static Error NotFound(string entity, string identifier) =>
        new("Error.NotFound", $"{entity} with identifier '{identifier}' was not found.");

    /// <summary>
    /// Creates a conflict error.
    /// </summary>
    public static Error Conflict(string message) => new("Error.Conflict", message);

    /// <summary>
    /// Creates an unauthorized error.
    /// </summary>
    public static Error Unauthorized(string message = "Unauthorized access.") =>
        new("Error.Unauthorized", message);

    /// <summary>
    /// Creates a forbidden error.
    /// </summary>
    public static Error Forbidden(string message = "Access is forbidden.") =>
        new("Error.Forbidden", message);

    /// <summary>
    /// Creates an internal error.
    /// </summary>
    public static Error Internal(string message) => new("Error.Internal", message);

    /// <summary>
    /// Creates an external service error.
    /// </summary>
    public static Error External(string service, string message) =>
        new($"Error.External.{service}", message);

    public override string ToString() => $"[{Code}] {Message}";
}

/// <summary>
/// Validation error containing multiple validation failures.
/// </summary>
public sealed record ValidationError : Error
{
    public IReadOnlyDictionary<string, string[]> Errors { get; }

    public ValidationError(IReadOnlyDictionary<string, string[]> errors)
        : base("Error.Validation", "One or more validation errors occurred.")
    {
        Errors = errors;
    }
}
