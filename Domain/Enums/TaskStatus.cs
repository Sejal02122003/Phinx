// --------------------------------------------------------------------------
// <copyright file="TaskStatus.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Domain.Enums;

/// <summary>
/// Status of a Phoenix task or operation.
/// </summary>
public enum TaskStatus
{
    /// <summary>Task is pending execution.</summary>
    Pending = 0,

    /// <summary>Task is currently in progress.</summary>
    InProgress = 1,

    /// <summary>Task completed successfully.</summary>
    Completed = 2,

    /// <summary>Task failed with errors.</summary>
    Failed = 3,

    /// <summary>Task was cancelled.</summary>
    Cancelled = 4,

    /// <summary>Task completed but with some errors.</summary>
    CompletedWithErrors = 5
}
