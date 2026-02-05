// ILdapService.cs - Phoenix Security
using System.DirectoryServices.Protocols;
using Phoenix.Core.Common;

namespace Phoenix.Core.Abstractions;

public interface ILdapService : IDisposable
{
    Task<Result<ILdapConnection>> ConnectAsync(string server, string username, string password, bool useSsl = true, CancellationToken cancellationToken = default);
    Task<Result<IReadOnlyList<LdapSearchResult>>> SearchAsync(string baseDn, string filter, string[] attributes, SearchScope scope = SearchScope.Subtree, int sizeLimit = 1000, CancellationToken cancellationToken = default);
    Task<Result> ModifyAsync(string distinguishedName, DirectoryAttributeModification modification, CancellationToken cancellationToken = default);
    Task<Result<RootDseInfo>> GetRootDseAsync(CancellationToken cancellationToken = default);
}

public interface ILdapConnection : IDisposable { string Server { get; } bool IsConnected { get; } }

public sealed class LdapSearchResult
{
    public required string DistinguishedName { get; init; }
    public required IReadOnlyDictionary<string, object?> Attributes { get; init; }
    public T? GetAttribute<T>(string name) => Attributes.TryGetValue(name, out var value) ? (T?)value : default;
    public string GetStringAttribute(string name) => GetAttribute<string>(name) ?? string.Empty;
}

public sealed record RootDseInfo
{
    public required string DefaultNamingContext { get; init; }
    public required string ConfigurationNamingContext { get; init; }
    public required string SchemaNamingContext { get; init; }
    public required string RootDomainNamingContext { get; init; }
    public required string DnsHostName { get; init; }
    public required string ServerName { get; init; }
    public required int ForestFunctionality { get; init; }
    public required int DomainFunctionality { get; init; }
    public required int DcFunctionality { get; init; }
}
