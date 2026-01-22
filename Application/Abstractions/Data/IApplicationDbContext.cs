using Domain.Computers;
using Microsoft.EntityFrameworkCore;

namespace Application.Abstractions.Data;

public interface IApplicationDbContext
{
    DbSet<Computer>  Computers { get; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}