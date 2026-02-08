namespace DepSafe;

/// <summary>
/// Classifies the kind of error for structured error handling.
/// </summary>
public enum ErrorKind
{
    None,
    NotFound,
    NetworkError,
    ParseError,
    RateLimited,
    InvalidInput,
    Timeout,
    ExternalToolNotFound,
    Unknown
}

/// <summary>
/// A discriminated result type for operations that can fail.
/// Zero-allocation value type with pattern matching support.
/// </summary>
public readonly record struct Result<T>
{
    private readonly T? _value;
    private readonly string? _error;

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public ErrorKind Kind { get; }

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException($"Cannot access Value on a failed Result. Error: {_error}");

    public string Error => IsFailure
        ? _error!
        : throw new InvalidOperationException("Cannot access Error on a successful Result.");

    private Result(T value)
    {
        IsSuccess = true;
        Kind = ErrorKind.None;
        _value = value;
        _error = null;
    }

    private Result(string error, ErrorKind kind)
    {
        IsSuccess = false;
        Kind = kind;
        _value = default;
        _error = error;
    }

    public static Result<T> Ok(T value) => new(value);
    public static Result<T> Fail(string error, ErrorKind kind = ErrorKind.Unknown) => new(error, kind);

    /// <summary>
    /// Returns the value if successful, or the fallback value if failed.
    /// Useful for graceful degradation patterns.
    /// </summary>
    public T ValueOr(T fallback) => IsSuccess ? _value! : fallback;

    public static implicit operator Result<T>(T value) => Ok(value);

    public override string ToString() =>
        IsSuccess ? $"Ok({_value})" : $"Fail({Kind}: {_error})";
}

/// <summary>
/// Non-generic Result for void operations and static factory methods.
/// </summary>
public readonly record struct Result
{
    private readonly string? _error;

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public ErrorKind Kind { get; }

    public string Error => IsFailure
        ? _error!
        : throw new InvalidOperationException("Cannot access Error on a successful Result.");

    private Result(bool success, string? error, ErrorKind kind)
    {
        IsSuccess = success;
        Kind = kind;
        _error = error;
    }

    public static Result Ok() => new(true, null, ErrorKind.None);
    public static Result Fail(string error, ErrorKind kind = ErrorKind.Unknown) => new(false, error, kind);

    public static Result<T> Ok<T>(T value) => Result<T>.Ok(value);
    public static Result<T> Fail<T>(string error, ErrorKind kind = ErrorKind.Unknown) => Result<T>.Fail(error, kind);

    public override string ToString() =>
        IsSuccess ? "Ok" : $"Fail({Kind}: {_error})";
}
