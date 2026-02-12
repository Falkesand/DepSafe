using DepSafe.Compliance;
using DepSafe.Models;
using DepSafe.Scoring;

namespace DepSafe.Tests;

public class TrendSnapshotIntegrationTests
{
    [Fact]
    public void BuildFromCraReport_AllFieldsMapped()
    {
        var report = new CraReport
        {
            GeneratedAt = new DateTime(2026, 2, 12, 14, 30, 0, DateTimeKind.Utc),
            ProjectPath = "/test/project",
            HealthScore = 78,
            HealthStatus = HealthStatus.Watch,
            ComplianceItems = [],
            OverallComplianceStatus = CraComplianceStatus.Compliant,
            Sbom = new SbomDocument
            {
                SpdxId = "SPDXRef-DOCUMENT",
                Name = "test-sbom",
                DocumentNamespace = "https://example.com/test",
                CreationInfo = new SbomCreationInfo
                {
                    Created = "2026-02-12T14:30:00Z",
                    Creators = ["Tool: DepSafe"]
                },
                Packages = [],
                Relationships = []
            },
            Vex = new VexDocument
            {
                Id = "https://example.com/vex/test",
                Author = "DepSafe",
                Timestamp = "2026-02-12T14:30:00Z",
                Statements = []
            },
            PackageCount = 12,
            TransitivePackageCount = 45,
            VulnerabilityCount = 3,
            CriticalPackageCount = 1,
            CraReadinessScore = 84,
            MaxUnpatchedVulnerabilityDays = 14,
            SbomCompletenessPercentage = 92,
            MaxDependencyDepth = 4,
            HasUnmaintainedPackages = false,
            ReportableVulnerabilityCount = 2
        };

        var snapshot = TrendAnalyzer.BuildSnapshot(report);

        Assert.Equal(report.GeneratedAt, snapshot.CapturedAt);
        Assert.Equal(report.ProjectPath, snapshot.ProjectPath);
        Assert.Equal(78, snapshot.HealthScore);
        Assert.Equal(84, snapshot.CraReadinessScore);
        Assert.Equal(3, snapshot.VulnerabilityCount);
        Assert.Equal(1, snapshot.CriticalPackageCount);
        Assert.Equal(2, snapshot.ReportableVulnerabilityCount);
        Assert.Equal(14, snapshot.MaxUnpatchedVulnerabilityDays);
        Assert.Equal(92, snapshot.SbomCompletenessPercentage);
        Assert.Equal(4, snapshot.MaxDependencyDepth);
        Assert.False(snapshot.HasUnmaintainedPackages);
        Assert.Equal(12, snapshot.PackageCount);
        Assert.Equal(45, snapshot.TransitivePackageCount);
    }
}
