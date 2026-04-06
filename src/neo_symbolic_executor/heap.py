from __future__ import annotations

from dataclasses import dataclass

from .expr import Expression, HeapRef, Sort, render_expr


@dataclass
class ArrayObject:
    elements: list[Expression]


@dataclass
class StructObject:
    elements: list[Expression]


@dataclass
class MapObject:
    entries: list[tuple[Expression, Expression]]


@dataclass
class BufferObject:
    data: bytearray


HeapObject = ArrayObject | StructObject | MapObject | BufferObject


def new_array_ref(object_id: int) -> HeapRef:
    return HeapRef(object_id=object_id, ref_sort=Sort.ARRAY)


def new_struct_ref(object_id: int) -> HeapRef:
    return HeapRef(object_id=object_id, ref_sort=Sort.STRUCT)


def new_map_ref(object_id: int) -> HeapRef:
    return HeapRef(object_id=object_id, ref_sort=Sort.MAP)


def new_buffer_ref(object_id: int) -> HeapRef:
    return HeapRef(object_id=object_id, ref_sort=Sort.BUFFER)


def clone_heap_object(obj: HeapObject) -> HeapObject:
    if isinstance(obj, ArrayObject):
        return ArrayObject(elements=list(obj.elements))
    if isinstance(obj, StructObject):
        return StructObject(elements=list(obj.elements))
    if isinstance(obj, MapObject):
        return MapObject(entries=list(obj.entries))
    return BufferObject(data=bytearray(obj.data))


def render_heap_snapshot(heap: dict[int, HeapObject]) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for object_id, obj in sorted(heap.items()):
        if isinstance(obj, ArrayObject):
            snapshot[f"array#{object_id}"] = [render_expr(item) for item in obj.elements]
        elif isinstance(obj, StructObject):
            snapshot[f"struct#{object_id}"] = [render_expr(item) for item in obj.elements]
        elif isinstance(obj, MapObject):
            snapshot[f"map#{object_id}"] = [
                {"key": render_expr(key), "value": render_expr(value)}
                for key, value in obj.entries
            ]
        else:
            snapshot[f"buffer#{object_id}"] = f"0x{bytes(obj.data).hex()}"
    return snapshot
