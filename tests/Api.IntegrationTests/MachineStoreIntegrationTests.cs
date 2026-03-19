using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.IntegrationTests.Infrastructure;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Api.IntegrationTests;

public class MachineStoreIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public MachineStoreIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task CrudMachine_ShouldCreateReadUpdateAndDelete()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var registerResponse = await client.PostAsJsonAsync("/computers", new
        {
            name = "PC-OPER-01",
            cpuId = "CPU-123",
            biosSerial = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            diskSerial = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            operatingSystem = "Windows 11",
            machineGuid = "GUID-123456"
        });
        Assert.Equal(HttpStatusCode.OK, registerResponse.StatusCode);

        int computerId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            computerId = await db.Computers
                .OrderByDescending(x => x.Id)
                .Select(x => x.Id)
                .FirstAsync();
        }

        var createResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/machines",
            new { computerId });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        var createdJson = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        var machineId = createdJson.RootElement.GetProperty("id").GetGuid();
        Assert.Equal(computerId, createdJson.RootElement.GetProperty("computerId").GetInt32());

        var listResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/machines");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var listJson = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.True(listJson.RootElement.GetProperty("count").GetInt32() >= 1);

        var getResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/machines/{machineId}");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

        var updateResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/machines/{machineId}",
            new { status = 2 });
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        var updateJson = JsonDocument.Parse(await updateResponse.Content.ReadAsStringAsync());
        Assert.Equal(2, updateJson.RootElement.GetProperty("status").GetInt32());

        var deleteResponse = await client.DeleteAsync($"/vaults/{ApiTestFactory.VaultId}/machines/{machineId}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        var getAfterDelete = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/machines/{machineId}");
        Assert.Equal(HttpStatusCode.NotFound, getAfterDelete.StatusCode);
    }
}
