import pytest

from mdebuilder.schema import SchemaModel, load_schema


@pytest.fixture(scope="session")
def model() -> SchemaModel:
    """The bundled Microsoft schema, parsed."""
    return SchemaModel(load_schema())
