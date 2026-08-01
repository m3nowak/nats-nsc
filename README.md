# nats-nsc

Limited python nsc utility equivalent, for user creation and signing JWTs.

[Documentation](https://m3nowak.github.io/nats-nsc/)
[PyPi](https://pypi.org/project/nats-nsc/)

## Development

The project uses [mise](https://mise.jdx.dev/) to install Python and uv. Set up
the development environment with:

```console
mise trust
mise install
mise run sync
```

The main project tasks are:

- `mise run check` runs linting, formatting checks, type checking, and tests.
- `mise run format` fixes lint violations and formats Python code.
- `mise run test` runs the test suite.
- `mise run docs` builds the documentation.
- `mise run build` builds the source and wheel distributions.
