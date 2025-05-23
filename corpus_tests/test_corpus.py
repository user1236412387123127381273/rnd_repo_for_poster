"""
Tests using bisa's decompiler. We use pytest-insta to create snapshots.
"""

# pylint: disable=import-error
from __future__ import annotations
import json
import logging
import re

import bisa
from bisa.analyses.decompiler.decompilation_options import PARAM_TO_OPTION

# Invoke this test script with the `pytest --insta` switch to enable the snapshot mechanism

logging.basicConfig(level=logging.CRITICAL, force=True)

SNAPSHOTS_REPO_BASE_URL = "https://github.com/project-purcellville/snapshots-0000/"


def analyze_binary(binary_path: str) -> dict:
    """
    Run the binary through CFG generation and extract the decompilation from the
    Decompiler analysis.

    The intention of this analysis function is to use as little bisa interfaces
    as possible since they may change over time. If they change, this script
    will need updating.
    """
    project = bisa.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = {}

    function: bisa.knowledge_plugins.functions.function.Function
    for function in cfg.functions.values():
        function.normalize()
        func_key = f"{function.addr}:{function.name}"

        # Wrapping in a try/except because the decompiler sometimes fails
        try:
            decomp = project.analyses.Decompiler(
                func=function,
                cfg=cfg,
                # setting show_casts to false because of non-determinism
                options=[
                    (
                        PARAM_TO_OPTION["structurer_cls"],
                        "Phoenix",
                    ),
                    (
                        PARAM_TO_OPTION["show_casts"],
                        False,
                    ),
                ],
            )
        except Exception as ex:  # pylint:disable=broad-exception-caught
            print(
                "\n".join(
                    [
                        f'Exception decompiling "{func_key}()" in "{binary_path}":',
                        f"{ex}\nContinuing with other functions.",
                    ]
                )
            )

        if decomp.codegen:
            decompilation[func_key] = decomp.codegen.text
        else:
            decompilation[func_key] = None

    return decompilation


def create_diffable_decompilation(decompiler_output: dict) -> str | None:
    """
    Convert the decompiler output `dict` into JSON, but also modify it to
    allow easy diffing (appending actual newlines '\n' to escaped newlines
    '\\n', etc.), returning the result as a string.
    """
    try:
        decompiler_json = json.dumps(decompiler_output)
        decompiler_json_newlined = re.sub("\\\\n", "\\\\n\n", decompiler_json)
    except Exception as ex:  # pylint:disable=broad-exception-caught
        print(f"Exception converting decompiler output to newlined-JSON:\n{ex}")
        return None
    return decompiler_json_newlined


def pytest_insta_snapshot_name(binary: str) -> str:
    """
    Return the undecorated snapshot name that `pytest-insta` will use to
    retrieve the snapshot from local storage in `./snapshots/`. Note that this
    will *not* contain the decorations that `pytest-insta` uses, like its
    `"<test-name>__<case-name>__"` prefix and `"__<#>.<ext>"` suffix.
    """
    return re.sub("/", "_", re.sub("^binaries/", "", binary)) + ".json.txt"


def test_decompilation(binary, snapshot):
    """
    In order to accommodate insta's need to have snapshots stored in a single
    file directly in the local `./snapshots/` directory, but also allow a
    reasonable comparison with the snapshots repo using github's pull request
    comparison, we pull down each snapshot from deeper within the snapshot
    repo's directory structure, but place it with a flat name (path delimiters
    replaced) in the `./snapshots/`, tweaking it to work with the standard
    way `pytest-insta` works (see `pytest_insta_snapshot_name()` above).

    Note that the snapshot should already be downloaded (by the workflow or
    manually) and placed in the snapshots directory. The name should be
    'corpus__decompilation__<binary-subpath-/-escaped>.json.txt__0.txt'. For
    example, the binary 'binaries/my/path/binary.exe' should be named
    'corpus__decompilation__my_path_binary.exe.json.txt__0.txt' in the
    local `./snapshots/` directory.

    This needs to stay in sync with the code that downloads the snapshots
    in `corpus_test.yml`.
    """
    decompilation = analyze_binary(binary)
    if not decompilation:
        # Message already emitted.
        return

    # Adds newlines after each newline literal '\\n'.
    diffable_decompilation = create_diffable_decompilation(decompilation)

    # This replaces path delimiters with underscores and appends ".json.txt".
    snapshot_name = pytest_insta_snapshot_name(binary)

    print(f'Loading snapshot "{snapshot_name}".')
    assert snapshot(snapshot_name) == diffable_decompilation
