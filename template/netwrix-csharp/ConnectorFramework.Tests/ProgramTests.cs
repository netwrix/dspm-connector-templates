using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

// Process-level env vars mutated in these tests are not thread-safe across parallel runs.
// Run this collection sequentially to avoid flaky interference with other test classes.
[Collection("Sequential")]
public class ProgramTests
{
    // ── IsJobMode ─────────────────────────────────────────────────────────────

    [Fact]
    public void IsJobMode_ReturnsTrue_WhenExecutionModeIsJob()
    {
        Environment.SetEnvironmentVariable("EXECUTION_MODE", "job");
        Environment.SetEnvironmentVariable("REQUEST_DATA", null);
        try
        {
            Assert.True(Program.IsJobMode());
        }
        finally
        {
            Environment.SetEnvironmentVariable("EXECUTION_MODE", null);
        }
    }

    [Fact]
    public void IsJobMode_ReturnsTrue_WhenRequestDataIsSet_AndExecutionModeIsAbsent()
    {
        Environment.SetEnvironmentVariable("EXECUTION_MODE", null);
        Environment.SetEnvironmentVariable("REQUEST_DATA", "{\"scanExecutionId\":\"abc\"}");
        try
        {
            Assert.True(Program.IsJobMode());
        }
        finally
        {
            Environment.SetEnvironmentVariable("REQUEST_DATA", null);
        }
    }

    [Fact]
    public void IsJobMode_ReturnsFalse_WhenNeitherIsSet()
    {
        Environment.SetEnvironmentVariable("EXECUTION_MODE", null);
        Environment.SetEnvironmentVariable("REQUEST_DATA", null);
        Assert.False(Program.IsJobMode());
    }

    [Fact]
    public void IsJobMode_ReturnsFalse_WhenExecutionModeIsNotJob()
    {
        Environment.SetEnvironmentVariable("EXECUTION_MODE", "http");
        Environment.SetEnvironmentVariable("REQUEST_DATA", null);
        try
        {
            Assert.False(Program.IsJobMode());
        }
        finally
        {
            Environment.SetEnvironmentVariable("EXECUTION_MODE", null);
        }
    }

    // ── BuildRequestPath ──────────────────────────────────────────────────────

    [Fact]
    public void BuildRequestPath_UsesRequestPath_WhenExplicitlySet()
    {
        Environment.SetEnvironmentVariable("REQUEST_PATH", "/connector/access_scan");
        Environment.SetEnvironmentVariable("FUNCTION_TYPE", null);
        try
        {
            Assert.Equal("/connector/access_scan", Program.BuildRequestPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("REQUEST_PATH", null);
        }
    }

    [Fact]
    public void BuildRequestPath_DerivesPathFromFunctionType_WhenRequestPathIsAbsent()
    {
        Environment.SetEnvironmentVariable("REQUEST_PATH", null);
        Environment.SetEnvironmentVariable("FUNCTION_TYPE", "access-scan");
        try
        {
            Assert.Equal("/connector/access_scan", Program.BuildRequestPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("FUNCTION_TYPE", null);
        }
    }

    [Fact]
    public void BuildRequestPath_DerivesPathFromFunctionType_ReplacingHyphensWithUnderscores()
    {
        Environment.SetEnvironmentVariable("REQUEST_PATH", null);
        Environment.SetEnvironmentVariable("FUNCTION_TYPE", "sensitive-data-scan");
        try
        {
            Assert.Equal("/connector/sensitive_data_scan", Program.BuildRequestPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("FUNCTION_TYPE", null);
        }
    }

    [Fact]
    public void BuildRequestPath_DefaultsToTestConnection_WhenBothAreAbsent()
    {
        Environment.SetEnvironmentVariable("REQUEST_PATH", null);
        Environment.SetEnvironmentVariable("FUNCTION_TYPE", null);
        Assert.Equal("/connector/test_connection", Program.BuildRequestPath());
    }

    [Fact]
    public void BuildRequestPath_PrefersRequestPath_OverFunctionType()
    {
        Environment.SetEnvironmentVariable("REQUEST_PATH", "/connector/access_scan");
        Environment.SetEnvironmentVariable("FUNCTION_TYPE", "sensitive-data-scan");
        try
        {
            Assert.Equal("/connector/access_scan", Program.BuildRequestPath());
        }
        finally
        {
            Environment.SetEnvironmentVariable("REQUEST_PATH", null);
            Environment.SetEnvironmentVariable("FUNCTION_TYPE", null);
        }
    }
}
