using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;
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
    public async Task UploadSiTRecords_SavesEachObjectToObjectsTable()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var models = new List<SitObjectImportModel>
        {
            new() { Id = Guid.NewGuid().ToString(), Type = Guid.NewGuid() },
            new() { Id = Guid.NewGuid().ToString(), Type = Guid.NewGuid() },
        };

        await facade.UploadSiTRecords(new CrawlContext(), models, [], [], isFinal: false);

        writerMock.Verify(w => w.SaveObject("objects", models[0], true), Times.Once);
        writerMock.Verify(w => w.SaveObject("objects", models[1], true), Times.Once);
    }

    [Fact]
    public async Task UploadSiTRecords_WhenIsFinalFalse_DoesNotFlush()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTRecords(new CrawlContext(), [], [], [], isFinal: false);

        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UploadSiTRecords_WhenIsFinalTrue_FlushesWriter()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTRecords(new CrawlContext(), [], [], [], isFinal: true);

        writerMock.Verify(w => w.FlushTablesAsync(CancellationToken.None), Times.Once);
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
    public async Task UploadSiTSchemaRecords_WhenIsFinalTrue_FlushesWriter()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);

        await facade.UploadSiTSchemaRecords(new CrawlContext(), "schema_table", [], isFinal: true);

        writerMock.Verify(w => w.FlushTablesAsync(CancellationToken.None), Times.Once);
    }

    // ── UploadActivityRecords ────────────────────────────────────────────────

    [Fact]
    public async Task UploadActivityRecords_SavesEachRecordToActivityRecordsTable()
    {
        var writerMock = WriterMock();
        var facade = CreateFacade(writerMock.Object);
        var records = new List<ActivityRecord> { new(), new() };

        await facade.UploadActivityRecords(records);

        writerMock.Verify(w => w.SaveObject("activity_records", It.IsAny<ActivityRecord>(), true), Times.Exactly(2));
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

    // ── DecryptServiceBusMessage ─────────────────────────────────────────────

    [Fact]
    public async Task DecryptServiceBusMessage_ThrowsNotSupportedException()
    {
        var facade = CreateFacade(WriterMock().Object);

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            facade.DecryptServiceBusMessage<object>("msg"));
    }
}
