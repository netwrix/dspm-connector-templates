using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class AACorePlatformFacadeTests
{
    private static AACorePlatformFacade CreateFacade(IScanWriter writer)
        => new(NullLogger<AACorePlatformFacade>.Instance, writer);

    private static Mock<IScanWriter> WriterMock()
    {
        var mock = new Mock<IScanWriter>();
        mock.Setup(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    // ── UploadSiTRecords ──────────────────────────────────────────────────────

    [Fact]
    public async Task UploadSiTRecords_ThrowsNotSupportedException()
    {
        var facade = CreateFacade(WriterMock().Object);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            facade.UploadSiTRecords(new CrawlContext(), [], [], [], isFinal: false));
    }

    // ── UploadSiTSchemaRecords ────────────────────────────────────────────────

    [Fact]
    public async Task UploadSiTSchemaRecords_SavesEachEntityToNamedTable()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var entities = new List<JsonObject> { new JsonObject(), new JsonObject() };

        await facade.UploadSiTSchemaRecords(new CrawlContext(), "schema_table", entities, isFinal: false);

        writerMock.Verify(w => w.SaveObject("schema_table", It.IsAny<JsonObject>(), true), Times.Exactly(2));
    }

    [Fact]
    public async Task UploadSiTSchemaRecords_WhenIsFinalFalse_DoesNotFlush()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTSchemaRecords(new CrawlContext(), "schema_table", [], isFinal: false);

        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UploadSiTSchemaRecords_IsFinalTrue_FlushesBuffersNotTables()
    {
        // isFinal=true triggers a non-closing buffer flush for incremental ClickHouse writes,
        // NOT the channel-closing FlushTablesAsync.
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTSchemaRecords(new CrawlContext(), "schema_table", [], isFinal: true);

        writerMock.Verify(w => w.FlushBuffers(It.IsAny<CancellationToken>()), Times.Once);
        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UploadSiTSchemaRecords_IsFinalFalse_NeitherFlushes()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTSchemaRecords(new CrawlContext(), "schema_table", [], isFinal: false);

        writerMock.Verify(w => w.FlushBuffers(It.IsAny<CancellationToken>()), Times.Never);
        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UploadSiTSchemaRecords_ConcurrentCallsWithIsFinalTrue_SavesAllEntities()
    {
        // Regression: concurrent workers each passing isFinal=true must not close channels or
        // cause data loss for workers still queued behind _writeLock.
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var entity = new JsonObject { ["id"] = "x" };

        var tasks = Enumerable.Range(0, 10).Select(_ =>
            facade.UploadSiTSchemaRecords(new CrawlContext(), "memberships", [entity], isFinal: true));

        await Task.WhenAll(tasks);

        writerMock.Verify(w => w.SaveObject("memberships", entity, true), Times.Exactly(10));
        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UploadSiTSchemaRecords_ConcurrentCalls_DoNotThrowAndSaveAllEntities()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var entity = new JsonObject { ["id"] = "x" };

        var tasks = Enumerable.Range(0, 10).Select(_ =>
            facade.UploadSiTSchemaRecords(new CrawlContext(), "permissions", [entity], isFinal: false));

        // Should complete without throwing InvalidOperationException from BatchManager's single-writer guard
        await Task.WhenAll(tasks);

        writerMock.Verify(w => w.SaveObject("permissions", entity, true), Times.Exactly(10));
    }

    // ── UploadActivityRecords ────────────────────────────────────────────────

    [Fact]
    public async Task UploadActivityRecords_IsNoOp_UntilTableExists()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadActivityRecords(new List<ActivityRecord> { new(), new() });

        writerMock.Verify(w => w.SaveObject(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<bool>()), Times.Never);
    }

    [Fact]
    public async Task UploadActivityRecords_NeverFlushesWriter()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadActivityRecords(new List<ActivityRecord> { new() });

        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── DecryptData ──────────────────────────────────────────────────────────

    [Fact]
    public async Task DecryptData_DeserializesJsonPayload()
    {
        var facade = CreateFacade(WriterMock().Object);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { name = "Alice" });

        var result = await facade.DecryptData<JsonElement>(Array.Empty<byte>(), payload);

        Assert.Equal("Alice", result.GetProperty("name").GetString());
    }

    [Fact]
    public async Task DecryptTenancyData_DeserializesJsonPayload()
    {
        var facade = CreateFacade(WriterMock().Object);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { tenantId = "t-1" });

        var result = await facade.DecryptTenancyData<JsonElement>(Array.Empty<byte>(), payload);

        Assert.Equal("t-1", result.GetProperty("tenantId").GetString());
    }

    // ── UploadCrawlCompletion ────────────────────────────────────────────────

    [Fact]
    public async Task UploadCrawlCompletion_SavesOneRowPerConnectorReference()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var connectorRef1 = Guid.NewGuid();
        var connectorRef2 = Guid.NewGuid();
        var context = new CrawlContext
        {
            TenancyReference = Guid.NewGuid(),
            ConnectorReferences = [connectorRef1, connectorRef2],
        };

        await facade.UploadCrawlCompletion(context);

        writerMock.Verify(w => w.SaveObject("crawl_completions", It.IsAny<object>(), false), Times.Exactly(2));
    }

    [Fact]
    public async Task UploadCrawlCompletion_FlushesAfterSaving()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var context = new CrawlContext
        {
            TenancyReference = Guid.NewGuid(),
            ConnectorReferences = [Guid.NewGuid()],
        };

        await facade.UploadCrawlCompletion(context);

        writerMock.Verify(w => w.FlushTablesAsync(CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task UploadCrawlCompletion_EmptyConnectorReferences_SavesNoRowsButStillFlushes()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var context = new CrawlContext
        {
            TenancyReference = Guid.NewGuid(),
            ConnectorReferences = [],
        };

        await facade.UploadCrawlCompletion(context);

        writerMock.Verify(w => w.SaveObject(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<bool>()), Times.Never);
        writerMock.Verify(w => w.FlushTablesAsync(CancellationToken.None), Times.Once);
    }

    // ── DecryptServiceBusMessage ─────────────────────────────────────────────

    [Fact]
    public async Task DecryptServiceBusMessage_ThrowsNotSupportedException()
    {
        var facade = CreateFacade(WriterMock().Object);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            facade.DecryptServiceBusMessage<object>("msg"));
    }
}
