// --------------------------------------------------------------------------
// <copyright file="ServiceCollectionExtensions.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     Dependency injection registration for Phoenix services.
// </copyright>
// --------------------------------------------------------------------------

using Microsoft.Extensions.DependencyInjection;
using Phoenix.Core.Services;
using Phoenix.Core.Services.ActiveDirectory.Tasks;
using Phoenix.Core.Services.MicrosoftAzure;
using Phoenix.Core.Services.MicrosoftAzure.Interfaces;
using Phoenix.Core.Services.Authentication;
using Phoenix.Core.Services.Authentication.MicrosoftAzure;
using Phoenix.Core.Services.EvidenceCollection.Tasks;
using Phoenix.Core.Services.TaskManager;

namespace Phoenix.Core;

/// <summary>
/// Extension methods for registering Phoenix services with DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all Phoenix infrastructure services.
    /// </summary>
    public static IServiceCollection AddPhoenixInfrastructure(this IServiceCollection services)
    {
        // Core logging services
        services.AddSingleton<PhoenixLoggerFactory>();
        services.AddScoped<IPhoenixLogger>(_ => PhoenixLoggerFactory.Create());

        //Task Manager service
        services.AddSingleton<ITaskManagerService, TaskManagerService>();
        // HTTP client for Azure services
        services.AddHttpClient();

        // Active Directory services
        services.AddScoped<IForestDiscoveryService, ForestDiscoveryService>();
        services.AddScoped<IAdIoeScanner, AdIoeScanner>();
        services.AddScoped<IKrbtgtPasswordService, KrbtgtPasswordService>();
        services.AddScoped<IDnsCleanupService, DnsCleanupService>();

        // AD Recovery Services (Tasks 3-13)
        services.AddScoped<IFsmoRoleSeizureService, FsmoRoleSeizureService>();
        services.AddScoped<IBuiltinAdminPasswordService, BuiltinAdminPasswordService>();
        services.AddScoped<IDcAccountPasswordService, DcAccountPasswordService>();
        services.AddScoped<IMassPasswordResetService, MassPasswordResetService>();
        services.AddScoped<IMetadataCleanupService, MetadataCleanupService>();
        services.AddScoped<ITrustPasswordService, TrustPasswordService>();
        services.AddScoped<ITrustPasswordResetService, TrustPasswordResetService>();
        services.AddScoped<ISysvolRestoreService, SysvolRestoreService>();
        services.AddScoped<IControlDispositionService, ControlDispositionService>();
        services.AddScoped<IGmsaService, GmsaService>();
        services.AddScoped<Phoenix.Core.Services.Authentication.IAdAuthenticationService, Phoenix.Core.Services.Authentication.ADAuthenticationService>();
        services.AddScoped<ICurrentUserPasswordService, CurrentUserPasswordService>();

        // MSAL-based Azure Authentication Service (singleton for state management)
        services.AddSingleton<IAzureAuthenticationService, AzureAuthenticationService>();
        services.AddSingleton<IGraphAuthenticationService, GraphAuthenticationService>();

        // Azure Task Services (Task 2-12)
        services.AddScoped<IBreakGlassService, BreakGlassService>();
        services.AddScoped<IAuthorizationPolicyService, AuthorizationPolicyService>();
        services.AddScoped<IConditionalAccessService, ConditionalAccessService>();
        services.AddScoped<IOnPremisesSyncService, OnPremisesSyncService>();
        services.AddScoped<IDomainFederationService, DomainFederationService>();
        services.AddScoped<IEntraDispositionService, EntraDispositionService>();
        services.AddScoped<IServicePrincipalReviewService, ServicePrincipalReviewService>();
        services.AddScoped<ISharePointGuardRailsService, SharePointGuardRailsService>();
        services.AddScoped<IAzureRbacService, AzureRbacService>();
        services.AddScoped<IExchangeDispositionService, ExchangeDispositionService>();
        services.AddScoped<ITemporaryAccessPassService, TemporaryAccessPassService>();

        return services;
    }

    /// <summary>
    /// Registers Phoenix services with HTTP client factory for Azure services.
    /// </summary>
    public static IServiceCollection AddPhoenixAzureServices(this IServiceCollection services)
    {
        // Register HttpClient instances for each Azure service
        services.AddHttpClient<IBreakGlassService, BreakGlassService>();
        services.AddHttpClient<IAuthorizationPolicyService, AuthorizationPolicyService>();
        services.AddHttpClient<IConditionalAccessService, ConditionalAccessService>();
        services.AddHttpClient<IOnPremisesSyncService, OnPremisesSyncService>();
        services.AddHttpClient<IDomainFederationService, DomainFederationService>();
        services.AddHttpClient<IEntraDispositionService, EntraDispositionService>();
        services.AddHttpClient<IServicePrincipalReviewService, ServicePrincipalReviewService>();
        services.AddHttpClient<ISharePointGuardRailsService, SharePointGuardRailsService>();
        services.AddHttpClient<IAzureRbacService, AzureRbacService>();
        services.AddHttpClient<IExchangeDispositionService, ExchangeDispositionService>();
        services.AddHttpClient<ITemporaryAccessPassService, TemporaryAccessPassService>();

        return services;
    }
}
