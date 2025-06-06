# pylint:disable=no-else-break
from __future__ import annotations
from bisect import bisect_left
import logging

from bisa.errors import BISACFGError, BISARuntimeError


l = logging.getLogger(name=__name__)


class Segment:
    """
    Representing a memory block. This is not the "Segment" in ELF memory model
    """

    __slots__ = ["end", "sort", "start"]

    def __init__(self, start, end, sort):
        """
        :param int start:   Start address.
        :param int end:     End address.
        :param str sort:    Type of the segment, can be code, data, etc.
        :return: None
        """

        self.start = start
        self.end = end
        self.sort = sort

    def __repr__(self):
        return f"[{self.start:#x}-{self.end:#x}, {self.sort}]"

    @property
    def size(self):
        """
        Calculate the size of the Segment.

        :return: Size of the Segment.
        :rtype: int
        """
        return self.end - self.start

    def copy(self):
        """
        Make a copy of the Segment.

        :return: A copy of the Segment instance.
        :rtype: bisa.analyses.cfg_fast.Segment
        """
        return Segment(self.start, self.end, self.sort)


class SegmentList:
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

    __slots__ = ["_bytes_occupied", "_list"]

    def __init__(self):
        self._list: list[Segment] = []
        self._bytes_occupied = 0

    #
    # Overridden methods
    #

    def __len__(self):
        return len(self._list)

    def __getitem__(self, idx: int) -> Segment:
        return self._list[idx]

    #
    # Private methods
    #

    def _insert_and_merge(self, address: int, size: int, sort: str, idx: int) -> None:
        """
        Determines whether the block specified by (address, size) should be merged with adjacent blocks.

        :param address: Starting address of the block to be merged.
        :param size: Size of the block to be merged.
        :param sort: Type of the block.
        :param idx: ID of the address.
        """

        # sanity check
        if idx > 0 and address + size <= self._list[idx - 1].start:
            # There is a bug, since _list[idx] must be the closest one that is less than the current segment
            l.warning("BUG FOUND: new segment should always be greater than _list[idx].")
            # Anyways, let's fix it.
            self._insert_and_merge(address, size, sort, idx - 1)
            return

        # Insert the block first
        # The new block might be overlapping with other blocks. _insert_and_merge_core will fix the overlapping.
        if idx == len(self._list):
            self._list.append(Segment(address, address + size, sort))
        else:
            self._list.insert(idx, Segment(address, address + size, sort))
        # Apparently _bytes_occupied will be wrong if the new block overlaps with any existing block. We will fix it
        # later
        self._bytes_occupied += size

        # Search forward to merge blocks if necessary
        pos = idx
        while pos < len(self._list):
            merged, pos, bytes_change = self._insert_and_merge_core(pos, "forward")

            if not merged:
                break

            self._bytes_occupied += bytes_change

        # Search backward to merge blocks if necessary
        pos = idx

        while pos > 0:
            merged, pos, bytes_change = self._insert_and_merge_core(pos, "backward")

            if not merged:
                break

            self._bytes_occupied += bytes_change

    def _insert_and_merge_core(self, pos: int, direction: str):
        """
        The core part of method _insert_and_merge.

        :param pos:         The starting position.
        :param direction:   If we are traversing forwards or backwards in the list. It determines where the "sort"
                                of the overlapping memory block comes from. If everything works as expected, "sort" of
                                the overlapping block is always equal to the segment occupied most recently.
        :return: A tuple of (merged (bool), new position to begin searching (int), change in total bytes (int)
        :rtype: tuple
        """

        bytes_changed = 0

        if direction == "forward":
            if pos == len(self._list) - 1:
                return False, pos, 0
            previous_segment = self._list[pos]
            previous_segment_pos = pos
            segment = self._list[pos + 1]
            segment_pos = pos + 1
        else:  # if direction == "backward":
            if pos == 0:
                return False, pos, 0
            segment = self._list[pos]
            segment_pos = pos
            previous_segment = self._list[pos - 1]
            previous_segment_pos = pos - 1

        merged = False
        new_pos = pos

        if segment.start <= previous_segment.end:
            # we should always have new_start+new_size >= segment.start

            if segment.sort == previous_segment.sort:
                # They are of the same sort - we should merge them!
                new_end = max(previous_segment.end, segment.start + segment.size)
                new_start = min(previous_segment.start, segment.start)
                new_size = new_end - new_start
                self._list[segment_pos] = Segment(new_start, new_end, segment.sort)
                self._list.pop(previous_segment_pos)
                bytes_changed = -(segment.size + previous_segment.size - new_size)

                merged = True
                new_pos = previous_segment_pos

            else:
                # Different sorts. It's a bit trickier.
                if segment.start == previous_segment.end:
                    # They are adjacent. Just don't merge.
                    pass
                else:
                    # They are overlapping. We will create one, two, or three different blocks based on how they are
                    # overlapping
                    new_segments = []
                    if segment.start < previous_segment.start:
                        new_segments.append(Segment(segment.start, previous_segment.start, segment.sort))

                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        new_segments.append(Segment(previous_segment.start, previous_segment.end, sort))

                        if segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        elif segment.end > previous_segment.end:
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                    else:  # segment.start >= previous_segment.start
                        if segment.start > previous_segment.start:
                            new_segments.append(Segment(previous_segment.start, segment.start, previous_segment.sort))
                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        if segment.end > previous_segment.end:
                            new_segments.append(Segment(segment.start, previous_segment.end, sort))
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                        elif segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.start, segment.end, sort))
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        else:
                            new_segments.append(Segment(segment.start, segment.end, sort))

                    # merge segments in new_segments array if they are of the same sort
                    i = 0
                    while len(new_segments) > 1 and i < len(new_segments) - 1:
                        s0 = new_segments[i]
                        s1 = new_segments[i + 1]
                        if s0.sort == s1.sort:
                            new_segments = (
                                new_segments[:i] + [Segment(s0.start, s1.end, s0.sort)] + new_segments[i + 2 :]
                            )
                        else:
                            i += 1

                    # Put new segments into self._list
                    old_size = sum(seg.size for seg in self._list[previous_segment_pos : segment_pos + 1])
                    new_size = sum(seg.size for seg in new_segments)
                    bytes_changed = new_size - old_size

                    if len(new_segments) == 2:
                        self._list[previous_segment_pos] = new_segments[0]
                        self._list[segment_pos] = new_segments[1]
                    elif len(new_segments) == 1:
                        self._list.pop(segment_pos)
                        self._list[previous_segment_pos] = new_segments[0]
                    elif len(new_segments) == 3:
                        self._list[previous_segment_pos] = new_segments[0]
                        self._list[segment_pos] = new_segments[1]
                        self._list.insert(segment_pos + 1, new_segments[2])
                    else:
                        # this does not happen for now, but may happen when the above logic changes
                        self._list = self._list[:previous_segment_pos] + new_segments + self._list[segment_pos + 1 :]

                    merged = True

                    if direction == "forward":
                        new_pos = previous_segment_pos + len(new_segments) - 1
                    else:
                        new_pos = previous_segment_pos

        return merged, new_pos, bytes_changed

    def _remove(self, init_address: int, init_size: int, init_idx: int) -> None:
        address = init_address
        size = init_size
        idx = init_idx

        while idx < len(self._list):
            segment = self._list[idx]
            if segment.start <= address:
                if address < segment.start + segment.size < address + size:
                    # |---segment---|
                    #      |---address + size---|
                    # shrink segment
                    segment.end = address
                    if segment.size == 0:
                        # remove the segment
                        self._list.pop(idx)
                    # adjust address
                    new_address = segment.start + segment.size
                    # adjust size
                    size = address + size - new_address
                    address = new_address
                    # update idx
                    idx = self.search(address)
                elif address < segment.start + segment.size and address + size <= segment.start + segment.size:
                    # |--------segment--------|
                    #    |--address + size--|
                    # break segment
                    seg0 = Segment(segment.start, address, segment.sort)
                    seg1 = Segment(address + size, segment.start + segment.size, segment.sort)
                    # remove the current segment
                    self._list.pop(idx)
                    if seg1.size > 0:
                        self._list.insert(idx, seg1)
                    if seg0.size > 0:
                        self._list.insert(idx, seg0)
                    # done
                    break
                else:
                    raise BISARuntimeError("Unreachable reached")
            else:  # if segment.start > address
                if address + size <= segment.start:
                    #                      |--- segment ---|
                    # |-- address + size --|
                    # no overlap
                    break
                if segment.start < address + size <= segment.start + segment.size:
                    #            |---- segment ----|
                    # |-- address + size --|
                    #
                    # update the start of the segment
                    segment.start = address + size
                    if segment.size == 0:
                        # remove the segment
                        self._list.pop(idx)
                    break
                if address + size > segment.start + segment.size:
                    #            |---- segment ----|
                    # |--------- address + size ----------|
                    self._list.pop(idx)  # remove the segment
                    new_address = segment.end
                    size = address + size - new_address
                    address = new_address
                    idx = self.search(address)
                else:
                    raise BISARuntimeError("Unreachable reached")

    def _dbg_output(self):
        """
        Returns a string representation of the segments that form this SegmentList

        :return: String representation of contents
        :rtype: str
        """
        s = "["
        lst = []
        for segment in self._list:
            lst.append(repr(segment))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
        """
        Iterates over list checking segments with same sort do not overlap

        :raise: Exception: if segments overlap space with same sort
        """
        # old_start = 0
        old_end = 0
        old_sort = ""
        for segment in self._list:
            if segment.start <= old_end and segment.sort == old_sort:
                raise BISACFGError("Error in SegmentList: blocks are not merged")
            # old_start = start
            old_end = segment.end
            old_sort = segment.sort

    #
    # Public methods
    #

    def search(self, addr: int) -> int:
        """
        Checks which segment that the address `addr` should belong to, and, returns the offset of that segment.
        Note that the address may not actually belong to the block.

        :param addr: The address to search
        :return: The offset of the segment.
        """

        off = bisect_left(self._list, addr, key=lambda x: x.start)
        if 0 < off <= len(self._list) and self._list[off - 1].end > addr:
            off -= 1
        return off

    def next_free_pos(self, address):
        """
        Returns the next free position with respect to an address, including that address itself

        :param address: The address to begin the search with (including itself)
        :return: The next free position
        """

        idx = self.search(address)
        if idx < len(self._list) and self._list[idx].start <= address < self._list[idx].end:
            # Occupied
            i = idx
            while i + 1 < len(self._list) and self._list[i].end == self._list[i + 1].start:
                i += 1
            if i == len(self._list):
                return self._list[-1].end

            return self._list[i].end

        return address

    def next_pos_with_sort_not_in(self, address, sorts, max_distance=None):
        """
        Returns the address of the next occupied block whose sort is not one of the specified ones.

        :param int address: The address to begin the search with (including itself).
        :param sorts:       A collection of sort strings.
        :param max_distance:    The maximum distance between `address` and the next position. Search will stop after
                                we come across an occupied position that is beyond `address` + max_distance. This check
                                will be disabled if `max_distance` is set to None.
        :return:            The next occupied position whose sort is not one of the specified ones, or None if no such
                            position exists.
        :rtype:             int or None
        """

        list_length = len(self._list)

        idx = self.search(address)
        if idx < list_length:
            # Occupied
            block = self._list[idx]

            if max_distance is not None and address + max_distance < block.start:
                return None

            if block.start <= address < block.end:
                # the address is inside the current block
                if block.sort not in sorts:
                    return address
                # tick the idx forward by 1
                idx += 1

            i = idx
            while i < list_length:
                if max_distance is not None and address + max_distance < self._list[i].start:
                    return None
                if self._list[i].sort not in sorts:
                    return self._list[i].start
                i += 1

        return None

    def is_occupied(self, address):
        """
        Check if an address belongs to any segment

        :param address: The address to check
        :return: True if this address belongs to a segment, False otherwise
        """

        idx = self.search(address)
        if len(self._list) <= idx:
            return False
        if self._list[idx].start <= address < self._list[idx].end:
            return True
        # TODO: It seems that this is never True. Should it be removed?
        return idx > 0 and address < self._list[idx - 1].end

    def occupied_by_sort(self, address: int) -> str | None:
        """
        Check if an address belongs to any segment, and if yes, returns the sort of the segment

        :param address: The address to check
        :return: Sort of the segment that occupies this address
        """

        idx = self.search(address)
        if len(self._list) <= idx:
            return None
        if self._list[idx].start <= address < self._list[idx].end:
            return self._list[idx].sort
        if idx > 0 and address < self._list[idx - 1].end:
            # TODO: It seems that this branch is never reached. Should it be removed?
            return self._list[idx - 1].sort
        return None

    def occupied_by(self, address: int) -> tuple[int, int, str] | None:
        """
        Check if an address belongs to any segment, and if yes, returns the beginning, the size, and the sort of the
        segment.

        :param address: The address to check
        """

        idx = self.search(address)
        if len(self._list) <= idx:
            return None
        if self._list[idx].start <= address < self._list[idx].end:
            block = self._list[idx]
            return block.start, block.size, block.sort
        if idx > 0 and address < self._list[idx - 1].end:
            # TODO: It seems that this branch is never reached. Should it be removed?
            block = self._list[idx - 1]
            return block.start, block.size, block.sort
        return None

    def occupy(self, address, size, sort):
        """
        Include a block, specified by (address, size), in this segment list.

        :param int address:     The starting address of the block.
        :param int size:        Size of the block.
        :param str sort:        Type of the block.
        :return: None
        """

        if size is None or size <= 0:
            # Cannot occupy a non-existent block
            return

        # l.debug("Occupying 0x%08x-0x%08x", address, address + size)
        if not self._list:
            self._list.append(Segment(address, address + size, sort))
            self._bytes_occupied += size
            return
        # Find adjacent element in our list
        idx = self.search(address)

        self._insert_and_merge(address, size, sort, idx)

        # self._debug_check()

    def release(self, address: int, size: int) -> None:
        """
        Remove a block, specified by (address, size), in this segment list.

        :param address: The starting address of the block.
        :param size:    Size of the block.
        """

        if size is None or size <= 0:
            # cannot release a non-existent block
            return
        if not self._list:
            return

        idx = self.search(address)
        if idx < len(self._list):
            self._remove(address, size, idx)

        # self._debug_check()

    def copy(self) -> SegmentList:
        """
        Make a copy of the SegmentList.

        :return: A copy of the SegmentList instance.
        """
        n = SegmentList()

        n._list = [a.copy() for a in self._list]
        n._bytes_occupied = self._bytes_occupied
        return n

    #
    # Properties
    #

    @property
    def occupied_size(self):
        """
        The sum of sizes of all blocks

        :return: An integer
        """

        return self._bytes_occupied

    @property
    def has_blocks(self):
        """
        Returns if this segment list has any block or not. !is_empty

        :return: True if it's not empty, False otherwise
        """

        return len(self._list) > 0
