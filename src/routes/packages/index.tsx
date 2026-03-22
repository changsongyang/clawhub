import { createFileRoute } from "@tanstack/react-router";
import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { fetchPackages, type PackageListItem } from "../../lib/packageApi";
import { familyLabel, packageCapabilityLabel } from "../../lib/packageLabels";

type PackageSearchState = {
  q?: string;
  cursor?: string;
  family?: "skill" | "code-plugin" | "bundle-plugin";
  official?: boolean;
  executesCode?: boolean;
};

type PackagesLoaderData = {
  items: PackageListItem[];
  nextCursor: string | null;
};

export const Route = createFileRoute("/packages/")({
  validateSearch: (search): PackageSearchState => ({
    q: typeof search.q === "string" && search.q.trim() ? search.q.trim() : undefined,
    cursor: typeof search.cursor === "string" && search.cursor ? search.cursor : undefined,
    family:
      search.family === "skill" || search.family === "code-plugin" || search.family === "bundle-plugin"
        ? search.family
        : undefined,
    official:
      search.official === true || search.official === "true" || search.official === "1"
        ? true
        : undefined,
    executesCode:
      search.executesCode === true ||
      search.executesCode === "true" ||
      search.executesCode === "1"
        ? true
        : undefined,
  }),
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }) => {
    const data = await fetchPackages({
      q: deps.q,
      cursor: deps.q ? undefined : deps.cursor,
      family: deps.family,
      isOfficial: deps.official,
      executesCode: deps.executesCode,
      limit: 50,
    });
    const items = "results" in data ? data.results.map((entry) => entry.package) : data.items;
    return {
      items,
      nextCursor: "results" in data ? null : data.nextCursor,
    } satisfies PackagesLoaderData;
  },
  component: PackagesIndex,
});

export function PackagesIndex() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  const { items, nextCursor } = Route.useLoaderData() as PackagesLoaderData;
  const [query, setQuery] = useState(search.q ?? "");

  useEffect(() => {
    setQuery(search.q ?? "");
  }, [search.q]);

  return (
    <main className="section">
      <header className="skills-header-top">
        <h1 className="section-title" style={{ marginBottom: 8 }}>
          Packages
        </h1>
        <p className="section-subtitle" style={{ marginBottom: 0 }}>
          Unified OpenClaw catalog: skills, code plugins, bundle plugins.
        </p>
      </header>

      <div className="card" style={{ display: "grid", gap: 12, marginBottom: 18 }}>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void navigate({
              search: (prev) => ({
                ...prev,
                cursor: undefined,
                q: query.trim() || undefined,
              }),
            });
          }}
          style={{ display: "grid", gap: 12 }}
        >
          <input
            className="input"
            placeholder="Search packages"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <select
              className="input"
              value={search.family ?? ""}
              onChange={(event) => {
                const value = event.target.value as PackageSearchState["family"] | "";
                void navigate({
                  search: (prev) => ({
                    ...prev,
                    cursor: undefined,
                    family: value || undefined,
                  }),
                });
              }}
            >
              <option value="">All families</option>
              <option value="skill">Skills</option>
              <option value="code-plugin">Code plugins</option>
              <option value="bundle-plugin">Bundle plugins</option>
            </select>
            <label className="tag" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <input
                type="checkbox"
                checked={search.official ?? false}
                onChange={(event) => {
                  void navigate({
                    search: (prev) => ({
                      ...prev,
                      cursor: undefined,
                      official: event.target.checked || undefined,
                    }),
                  });
                }}
              />
              Official only
            </label>
            <label className="tag" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <input
                type="checkbox"
                checked={search.executesCode ?? false}
                onChange={(event) => {
                  void navigate({
                    search: (prev) => ({
                      ...prev,
                      cursor: undefined,
                      executesCode: event.target.checked || undefined,
                    }),
                  });
                }}
              />
              Executes code
            </label>
            <Link className="btn" to="/upload" search={{ updateSlug: undefined }}>
              Publish Skill
            </Link>
            <Link className="btn" to="/packages/new">
              Publish Plugin
            </Link>
          </div>
        </form>
      </div>

      {items.length === 0 ? (
        <div className="card">No packages match that filter.</div>
      ) : (
        <>
          <div className="grid">
            {items.map((item) => (
              <Link
                key={item.name}
                to="/packages/$name"
                params={{ name: item.name }}
                className="skill-card"
              >
                <div className="skill-card-tags">
                  <span className="tag">{familyLabel(item.family)}</span>
                  <span className={`tag ${item.executesCode ? "tag-accent" : ""}`}>
                    {packageCapabilityLabel(item.family, item.executesCode)}
                  </span>
                  {item.isOfficial ? <span className="tag">Official</span> : null}
                  {item.verificationTier ? <span className="tag">{item.verificationTier}</span> : null}
                </div>
                <div className="skill-card-title">{item.displayName}</div>
                <div className="skills-row-slug">{item.name}</div>
                <div className="skill-card-summary">
                  {item.summary ?? "No summary provided."}
                </div>
                <div className="skill-card-footer skill-card-footer-rows">
                  <div className="stat">Channel: {item.channel}</div>
                  <div className="stat">
                    {item.ownerHandle ? `by ${item.ownerHandle}` : "community package"}
                  </div>
                  <div className="stat">
                    {item.latestVersion ? `v${item.latestVersion}` : "No releases yet"}
                  </div>
                </div>
              </Link>
            ))}
          </div>
          {!search.q && (search.cursor || nextCursor) ? (
            <div
              className="card"
              style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "space-between", marginTop: 18 }}
            >
              <div className="section-subtitle" style={{ margin: 0 }}>
                Browsing {items.length} package{items.length === 1 ? "" : "s"} per page.
              </div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                {search.cursor ? (
                  <button
                    className="btn"
                    type="button"
                    onClick={() => {
                      void navigate({
                        search: (prev) => ({
                          ...prev,
                          cursor: undefined,
                        }),
                      });
                    }}
                  >
                    First page
                  </button>
                ) : null}
                {nextCursor ? (
                  <button
                    className="btn btn-primary"
                    type="button"
                    onClick={() => {
                      void navigate({
                        search: (prev) => ({
                          ...prev,
                          cursor: nextCursor,
                        }),
                      });
                    }}
                  >
                    Next page
                  </button>
                ) : null}
              </div>
            </div>
          ) : null}
        </>
      )}
    </main>
  );
}
