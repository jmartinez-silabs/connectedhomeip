# src/python_testing/matter_testing_infrastructure/chip/typings/chip/testing/pics.py

import typing


def attribute_pics_str(pics_base: str, id: int) -> str: ...
def accepted_cmd_pics_str(pics_base: str, id: int) -> str: ...
def generated_cmd_pics_str(pics_base: str, id: int) -> str: ...
def feature_pics_str(pics_base: str, bit: int) -> str: ...
def server_pics_str(pics_base: str) -> str: ...
def client_pics_str(pics_base: str) -> str: ...
def parse_pics(lines: typing.List[str]) -> dict[str, bool]: ...
def parse_pics_xml(contents: str) -> dict[str, bool]: ...
def read_pics_from_file(path: str) -> dict[str, bool]: ...
