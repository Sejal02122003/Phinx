// --------------------------------------------------------------------------
// <copyright file="EntityBase.cs" company="NCS Dojo">
//     © 2026 NCS Dojo. All rights reserved.
// </copyright>
// --------------------------------------------------------------------------

namespace Phoenix.Core.Domain.Entities;

/// <summary>
/// Base class for all domain entities with audit trail support.
/// </summary>
public abstract class EntityBase
{
    /// <summary>
    /// Gets or sets the unique identifier.
    /// </summary>
    public Guid Id { get; protected init; }

    /// <summary>
    /// Gets or sets the creation timestamp.
    /// </summary>
    public DateTimeOffset CreatedAt { get; protected init; }

    /// <summary>
    /// Gets or sets the last modification timestamp.
    /// </summary>
    public DateTimeOffset? ModifiedAt { get; protected set; }

    /// <summary>
    /// Gets or sets the user who created this entity.
    /// </summary>
    public string? CreatedBy { get; protected init; }

    /// <summary>
    /// Gets or sets the user who last modified this entity.
    /// </summary>
    public string? ModifiedBy { get; protected set; }

    /// <summary>
    /// Determines whether the specified entity is equal to this entity.
    /// </summary>
    public override bool Equals(object? obj)
    {
        if (obj is not EntityBase other) return false;
        if (ReferenceEquals(this, other)) return true;
        if (GetType() != other.GetType()) return false;
        return Id == other.Id;
    }

    /// <summary>
    /// Returns a hash code for this entity.
    /// </summary>
    public override int GetHashCode() => Id.GetHashCode();

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(EntityBase? left, EntityBase? right)
    {
        if (left is null) return right is null;
        return left.Equals(right);
    }

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(EntityBase? left, EntityBase? right) => !(left == right);
}
