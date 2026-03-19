using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.IntegrationTests.Infrastructure;
using Xunit;

namespace Api.IntegrationTests;

public class AdMapStoreIntegrationTests : IClassFixture<ApiTestFactory>
{
    private readonly ApiTestFactory _factory;

    public AdMapStoreIntegrationTests(ApiTestFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task CrudAdMap_ShouldCreateReadUpdateAndDelete()
    {
        await _factory.EnsureInitializedAsync();
        using var client = _factory.CreateClient();

        var createResponse = await client.PostAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/ad-maps",
            new
            {
                groupId = "PLT\\grp-vault-readers",
                permission = 1,
                isActive = true
            });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        var createdJson = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        var adMapId = createdJson.RootElement.GetProperty("id").GetGuid();
        Assert.Equal("PLT\\grp-vault-readers", createdJson.RootElement.GetProperty("groupId").GetString());

        var listResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/ad-maps");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var listJson = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync());
        Assert.True(listJson.RootElement.GetProperty("count").GetInt32() >= 1);

        var getResponse = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/ad-maps/{adMapId}");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

        var updateResponse = await client.PutAsJsonAsync(
            $"/vaults/{ApiTestFactory.VaultId}/ad-maps/{adMapId}",
            new
            {
                permission = 3,
                isActive = false
            });
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        var updateJson = JsonDocument.Parse(await updateResponse.Content.ReadAsStringAsync());
        Assert.Equal(3, updateJson.RootElement.GetProperty("permission").GetInt32());
        Assert.False(updateJson.RootElement.GetProperty("isActive").GetBoolean());

        var listWithInactive = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/ad-maps?includeInactive=true");
        Assert.Equal(HttpStatusCode.OK, listWithInactive.StatusCode);

        var deleteResponse = await client.DeleteAsync($"/vaults/{ApiTestFactory.VaultId}/ad-maps/{adMapId}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        var getAfterDelete = await client.GetAsync($"/vaults/{ApiTestFactory.VaultId}/ad-maps/{adMapId}");
        Assert.Equal(HttpStatusCode.NotFound, getAfterDelete.StatusCode);
    }
}
