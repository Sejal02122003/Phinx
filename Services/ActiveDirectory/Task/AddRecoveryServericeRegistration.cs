// --------------------------------------------------------------------------
// <copyright file="AdRecoveryServiceRegistration.cs" company="Phoenix IR Platform">
//     © 2026 Phoenix IR Platform. All rights reserved.
//     DI registration for all AD recovery services.
// </copyright>
// --------------------------------------------------------------------------

using Microsoft.Extensions.DependencyInjection;

namespace Phoenix.Core.Services.ActiveDirectory.Tasks;

public static class AdRecoveryServiceRegistration
{
    /// <summary>
    /// Adds all AD recovery services to the service collection.
    /// </summary>
    public static Microsoft.Extensions.DependencyInjection.IServiceCollection AddAdRecoveryServices(
        this Microsoft.Extensions.DependencyInjection.IServiceCollection services)
    {
        services.AddSingleton<IFsmoRoleSeizureService, FsmoRoleSeizureService>();
        services.AddSingleton<IBuiltinAdminPasswordService, BuiltinAdminPasswordService>();
        services.AddSingleton<IDcAccountPasswordService, DcAccountPasswordService>();
        services.AddSingleton<IMassPasswordResetService, MassPasswordResetService>();
        services.AddSingleton<IMetadataCleanupService, MetadataCleanupService>();
        services.AddSingleton<ITrustPasswordResetService, TrustPasswordResetService>();
        services.AddSingleton<ISysvolRestoreService, SysvolRestoreService>();
        services.AddSingleton<IControlDispositionService, ControlDispositionService>();
        services.AddSingleton<IGmsaService, GmsaService>();
        services.AddSingleton<IDnsCleanupService, DnsCleanupService>();

        return services;
    }
}

