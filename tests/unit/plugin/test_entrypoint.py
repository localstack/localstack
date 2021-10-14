import pytest

from localstack.plugin.core import PluginSpec
from localstack.plugin.entrypoint import EntryPoint, spec_to_entry_point, to_entry_point_dict

from .plugins import sample_plugins


def test_spec_to_entry_point():
    spec = PluginSpec("my.namespace", "zeplugin", sample_plugins.AbstractSamplePlugin)
    ep = spec_to_entry_point(spec)

    assert ep.name == "zeplugin"
    assert ep.group == "my.namespace"
    assert ep.value == "tests.unit.plugin.plugins.sample_plugins:AbstractSamplePlugin"


def test_to_entry_point_dict():
    eps = [
        EntryPoint("foo", "MyFooPlugin1", "group.a"),
        EntryPoint("bar", "MyBarPlugin", "group.a"),
        EntryPoint("foo", "MyFooPlugin3", "group.b"),
    ]

    ep_dict = to_entry_point_dict(eps)

    assert "group.a" in ep_dict
    assert "group.b" in ep_dict

    assert "foo=MyFooPlugin1" in ep_dict["group.a"]
    assert "bar=MyBarPlugin" in ep_dict["group.a"]
    assert len(ep_dict["group.a"]) == 2

    assert "foo=MyFooPlugin3" in ep_dict["group.b"]
    assert len(ep_dict["group.b"]) == 1


def test_to_entry_point_dict_duplicates():
    eps = [
        EntryPoint("foo", "MyFooPlugin1", "group_a"),
        EntryPoint("foo", "MyFooPlugin2", "group_a"),
    ]

    with pytest.raises(ValueError) as ex:
        to_entry_point_dict(eps)

    ex.match("Duplicate entry point group_a foo")
