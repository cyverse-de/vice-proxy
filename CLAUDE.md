# General Code Guidelines
* Keep code succinct.
* Add validation both in the backend and frontend.
* Don't repeat yourself needlessly.
* Don't use multiple inheritance.
* Prefer composition over inheritance for new first-party types.
* Use table-driven tests rather than lots of small, similar tests.
* Add doc comments to publicly available methods and functions.
* Document code succinctly but thoroughly.
* Use type hinting in Python.
* Generally treat warnings as errors unless fixing the warning would cause difficult to fix breakages.
* Prefer using the standard library over adding new dependencies unless adding a new dependency is truly the more effective option or is the de-facto standard.
* Do a prettification/clean up pass on all generated code.
* Add good comments to code that may be confusing or doesn't behave in a standard way.
* Add comments to code changed as part of a pull request.
* Keep comments succinct, but thorough.
* Check for duplicated code. Don't duplicate interfaces or implementations across files, modules, packages, libraries, etc. Use one canonical version.
* Split up files if they get too long.


# API Design Guidelines
* DELETE operations should be idempotent: deleting a resource that doesn't exist should succeed silently (return nil/success), not return a "not found" error. Apply this consistently across all delete operations.
* When porting from an existing service, match the original API contract for required fields unless explicitly told to change it. Don't add optionality to update requests unless the original API supported it.


# Guidelines for Python programming language projects
* Use 'uv' for building, running, and managing Python projects. See https://docs.astral.sh/uv/ for documentation.
* Use 'ruff' for linting and formatting Python code. See https://docs.astral.sh/ruff/ for documentation.


# Guidelines for Go programming language projects

## Language & tooling
* Follow the standards outlined in Effective Go, found at https://go.dev/doc/effective_go.
* Use the `goimport` tool to format import statements.
* Use the `gofmt` tool to format code.
* Use `golangci-lint` to lint code. See https://golangci-lint.run/docs/ for documentation.
* Do not ignore returned errors.
* Use typed errors (custom error types with `errors.As`) for domain-specific error conditions like "not found". Never use string matching on error messages.
* When a file exceeds ~300 lines, consider splitting it by entity/domain type (e.g., one file per database entity: quicklaunches.go, favorites.go, settings.go).
* Before defining a new interface, search the codebase for an existing one with the same method set. Use type aliases or imports rather than duplicating.

## REST API & database patterns
* Always thread `context.Context` through the full call chain:
  - Extract context in Echo handlers with `c.Request().Context()`.
  - Pass context to transaction-starting functions (e.g., `BeginTx(ctx)`).
  - Use `*Context` method variants (`ExecContext`, `QueryRowContext`, etc.) for all database operations.
* All database functions should require a transaction (`Tx`) parameter. Never have database functions that operate outside a transaction.
* When a database query can fail for multiple reasons, always check for `sql.ErrNoRows` separately from other errors. A broken connection is not the same as a missing row.
* Prefer constructor injection for dependencies (HTTP clients, database connections, loggers) over package-level variables. This improves testability and makes dependencies explicit.
* Use `url.URL.JoinPath()` for building URLs with path components. It handles path escaping and trailing slash normalization automatically. Parse base URLs once in constructors, not on every request.


# CyVerse service integration notes
* The data-info `/path-info` endpoint returns HTTP 200 even for inaccessible paths; check for path presence in the response body rather than relying on status codes.
* Use `ignore-missing=true` when calling data-info to handle missing files gracefully.
* Treat HTTP 500 from external services as a real error, not "resource inaccessible."


# Docker guidelines
* Use '--network host' with local Docker containers by default.
* Use '--network host' with Docker if you encounter DNS issues in containers.


# Kubernetes guidelines
* The kubeconfig file for the QA environment is located at `~/.kube/qa.conf`.
* The kubeconfig file for the production environment is located at `~/.kube/prod.conf`.
* The kubeconfig file for the local cluster is located at `~/.kube/local-admin.conf`.
* Use QA kubeconfig file unless told explicitly otherwise.
* Don't use the production environment kubeconfig file unless explicitly told to and ask permission first anyway.
