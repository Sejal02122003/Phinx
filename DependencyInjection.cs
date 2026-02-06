// --------------------------------------------------------------------------
// <copyright file="DependencyInjection.cs" company="Phoenix Security">
//     Copyright © 2026 Phoenix Security. All rights reserved.
// </copyright>
// --------------------------------------------------------------------------

using Microsoft.Extensions.DependencyInjection;
using Phoenix.Core.Security;
using Phoenix.Core.Services.Orchestration;

namespace Phoenix.Core;

/// <summary>
/// Dependency injection configuration for Phoenix.Core.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds Phoenix Core services to the dependency injection container.
    /// </summary>
    public static IServiceCollection AddPhoenixCore(this IServiceCollection services)
    {
        // Register the IOE catalog as a singleton
        services.AddSingleton<IIoeCatalog, IoeCatalogService>();

        // Register the Task Orchestration service
        services.AddSingleton<ITaskOrchestrationService, TaskOrchestrationService>();

        return services;
    }
}

/// <summary>
/// Interface for IOE catalog operations.
/// </summary>
public interface IIoeCatalog
{
    IReadOnlyList<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetAll();
    IEnumerable<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetByCategory(Phoenix.Core.Domain.Enums.IoeCategory category);
    IEnumerable<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetBySeverity(Phoenix.Core.Domain.Enums.IoeSeverity severity);
    Phoenix.Core.Domain.Entities.IndicatorOfExposure? GetById(string ioeId);
}

/// <summary>
/// IOE catalog service implementation.
/// </summary>
internal sealed class IoeCatalogService : IIoeCatalog
{
    public IReadOnlyList<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetAll() => IoeCatalog.GetAll();
    public IEnumerable<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetByCategory(Phoenix.Core.Domain.Enums.IoeCategory category) => IoeCatalog.GetByCategory(category);
    public IEnumerable<Phoenix.Core.Domain.Entities.IndicatorOfExposure> GetBySeverity(Phoenix.Core.Domain.Enums.IoeSeverity severity) => IoeCatalog.GetBySeverity(severity);
    public Phoenix.Core.Domain.Entities.IndicatorOfExposure? GetById(string ioeId) => IoeCatalog.GetById(ioeId);
}
