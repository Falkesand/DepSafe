namespace DepSafe.Tests;

public class ResultTests
{
    [Fact]
    public void Ok_ReturnsSuccessfulResult()
    {
        var result = Result<int>.Ok(42);

        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
        Assert.Equal(42, result.Value);
        Assert.Equal(ErrorKind.None, result.Kind);
    }

    [Fact]
    public void Fail_ReturnsFailedResult()
    {
        var result = Result<int>.Fail("not found", ErrorKind.NotFound);

        Assert.True(result.IsFailure);
        Assert.False(result.IsSuccess);
        Assert.Equal("not found", result.Error);
        Assert.Equal(ErrorKind.NotFound, result.Kind);
    }

    [Fact]
    public void Fail_DefaultKind_IsUnknown()
    {
        var result = Result<int>.Fail("something broke");

        Assert.Equal(ErrorKind.Unknown, result.Kind);
    }

    [Fact]
    public void Value_OnFailure_Throws()
    {
        var result = Result<int>.Fail("broken");

        var ex = Assert.Throws<InvalidOperationException>(() => result.Value);
        Assert.Contains("broken", ex.Message);
    }

    [Fact]
    public void Error_OnSuccess_Throws()
    {
        var result = Result<int>.Ok(42);

        Assert.Throws<InvalidOperationException>(() => result.Error);
    }

    [Fact]
    public void ValueOr_OnSuccess_ReturnsValue()
    {
        var result = Result<int>.Ok(42);

        Assert.Equal(42, result.ValueOr(0));
    }

    [Fact]
    public void ValueOr_OnFailure_ReturnsFallback()
    {
        var result = Result<int>.Fail("broken");

        Assert.Equal(99, result.ValueOr(99));
    }

    [Fact]
    public void ImplicitConversion_CreatesSuccessResult()
    {
        Result<string> result = "hello";

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
    }

    [Fact]
    public void StaticFactory_Ok_CreatesSuccess()
    {
        var result = Result.Ok(42);

        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void StaticFactory_Fail_CreatesFailure()
    {
        var result = Result.Fail<int>("error", ErrorKind.ParseError);

        Assert.True(result.IsFailure);
        Assert.Equal("error", result.Error);
        Assert.Equal(ErrorKind.ParseError, result.Kind);
    }

    [Fact]
    public void NonGeneric_Ok_ReturnsSuccess()
    {
        var result = Result.Ok();

        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
        Assert.Equal(ErrorKind.None, result.Kind);
    }

    [Fact]
    public void NonGeneric_Fail_ReturnsFailure()
    {
        var result = Result.Fail("network down", ErrorKind.NetworkError);

        Assert.True(result.IsFailure);
        Assert.Equal("network down", result.Error);
        Assert.Equal(ErrorKind.NetworkError, result.Kind);
    }

    [Fact]
    public void NonGeneric_Error_OnSuccess_Throws()
    {
        var result = Result.Ok();

        Assert.Throws<InvalidOperationException>(() => result.Error);
    }

    [Fact]
    public void PatternMatching_WorksWithSwitch()
    {
        var result = Result<int>.Fail("rate limited", ErrorKind.RateLimited);

        var message = result.Kind switch
        {
            ErrorKind.RateLimited => "slow down",
            ErrorKind.NotFound => "missing",
            _ => "other"
        };

        Assert.Equal("slow down", message);
    }

    [Fact]
    public void ToString_Success_ContainsValue()
    {
        var result = Result<int>.Ok(42);

        Assert.Equal("Ok(42)", result.ToString());
    }

    [Fact]
    public void ToString_Failure_ContainsKindAndError()
    {
        var result = Result<int>.Fail("bad parse", ErrorKind.ParseError);

        Assert.Equal("Fail(ParseError: bad parse)", result.ToString());
    }

    [Fact]
    public void NonGeneric_ToString_Success()
    {
        Assert.Equal("Ok", Result.Ok().ToString());
    }

    [Fact]
    public void NonGeneric_ToString_Failure()
    {
        var result = Result.Fail("oops", ErrorKind.Timeout);

        Assert.Equal("Fail(Timeout: oops)", result.ToString());
    }

    [Fact]
    public void AllErrorKinds_Exist()
    {
        var kinds = Enum.GetValues<ErrorKind>();

        Assert.Contains(ErrorKind.None, kinds);
        Assert.Contains(ErrorKind.NotFound, kinds);
        Assert.Contains(ErrorKind.NetworkError, kinds);
        Assert.Contains(ErrorKind.ParseError, kinds);
        Assert.Contains(ErrorKind.RateLimited, kinds);
        Assert.Contains(ErrorKind.InvalidInput, kinds);
        Assert.Contains(ErrorKind.Timeout, kinds);
        Assert.Contains(ErrorKind.Unknown, kinds);
    }
}
