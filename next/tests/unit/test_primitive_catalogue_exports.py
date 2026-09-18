import importlib

from claasp_next import primitives
from claasp_next.primitives._catalogue_exports import ALL_EXPORTS, CATEGORY_EXPORTS


def test_all_142_catalogue_classes_are_public_at_top_level_and_by_category():
    assert len(ALL_EXPORTS) == 142
    assert sum(map(len, CATEGORY_EXPORTS.values())) == 142
    for category, exports in CATEGORY_EXPORTS.items():
        category_module = importlib.import_module(f"claasp_next.primitives.{category}")
        for name, module_name in exports.items():
            expected = getattr(importlib.import_module(module_name), name)
            assert getattr(primitives, name) is expected
            assert getattr(category_module, name) is expected
            assert name in primitives.__all__
            assert name in category_module.__all__


def test_unknown_catalogue_export_is_an_attribute_error():
    try:
        primitives.NotAPrimitive
    except AttributeError as error:
        assert error.args == ("NotAPrimitive",)
    else:
        raise AssertionError("unknown primitive export was accepted")
