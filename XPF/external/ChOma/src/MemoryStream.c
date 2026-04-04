#include "MemoryStream.h"
#include "Util.h"

int memory_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *outBuf)
{
    if (stream->read) {
        int ret = stream->read(stream, offset, size, outBuf);
        if (ret != size) { return -1; }
        return 0;
    }
    return -1;
}

int memory_stream_write(MemoryStream *stream, uint64_t offset, size_t size, const void *inBuf)
{
    if (stream->write) {
        int ret = stream->write(stream, offset, size, inBuf);
        if (ret != size) { return -1; }
        return 0;
    }
    return -1;
}

int memory_stream_insert(MemoryStream *stream, uint64_t offset, size_t size, const void *inBuf)
{
    if (!(stream->flags & MEMORY_STREAM_FLAG_MUTABLE)) goto fail;

    size_t streamSize = memory_stream_get_size(stream);
    if (memory_stream_expand(stream, 0, size) != 0) goto fail;
    if (memory_stream_copy_data(stream, offset, stream, offset + size, streamSize-offset) != 0) goto fail;
    if (memory_stream_write(stream, offset, size, inBuf) != 0) goto fail;
    return 0;

fail:
    printf("Error: memory_stream_insert failed\n");
    return -1;
}

int memory_stream_delete(MemoryStream *stream, uint64_t offset, size_t size)
{
    if (size == 0) return 0;
    if (!(stream->flags & MEMORY_STREAM_FLAG_MUTABLE)) goto fail;

    size_t streamSize = memory_stream_get_size(stream);
    if (memory_stream_copy_data(stream, offset+size, stream, offset, streamSize-(offset+size)) != 0) goto fail;
    if (memory_stream_trim(stream, 0, size) != 0) goto fail;
    return 0;

fail:
    printf("Error: memory_stream_delete failed\n");
    return -1;
}

int memory_stream_read_string(MemoryStream *stream, uint64_t offset, char **outString)
{
    size_t size = 0;
    char c = 1;
    while (c != 0) {
        int r = memory_stream_read(stream, offset+size, sizeof(c), &c);
        if (r != 0) return r;
        size++;
    }

    *outString = malloc(size+1);
    return memory_stream_read(stream, offset, size+1, *outString);
}

int memory_stream_write_string(MemoryStream *stream, uint64_t offset, const char *string)
{
    size_t size = strlen(string) + 1;
    return memory_stream_write(stream, offset, size, string);
}

size_t memory_stream_get_size(MemoryStream *stream)
{
    if (stream->getSize) {
        size_t sizeOut;
        if (stream->getSize(stream, &sizeOut) == 0) return sizeOut;
    }
    return MEMORY_STREAM_SIZE_INVALID;
}

uint8_t *memory_stream_get_raw_pointer(MemoryStream *stream)
{
    if (stream->getRawPtr) {
        return stream->getRawPtr(stream);
    }
    return NULL;
}

uint32_t memory_stream_get_flags(MemoryStream *stream)
{
    return stream->flags;
}

void _memory_stream_clone(MemoryStream *clone, MemoryStream *stream)
{
    clone->read = stream->read;
    clone->write = stream->write;
    clone->getSize = stream->getSize;
    clone->getRawPtr = stream->getRawPtr;

    clone->trim = stream->trim;
    clone->expand = stream->expand;

    clone->softclone = stream->softclone;
    clone->hardclone = stream->hardclone;
    clone->free = stream->free;
}

MemoryStream *memory_stream_softclone(MemoryStream *stream)
{
    if (stream->softclone) {
        MemoryStream *clone = stream->softclone(stream);
        if (clone) {
            _memory_stream_clone(clone, stream);
            return clone;
        }
    }
    return NULL;
}

MemoryStream *memory_stream_hardclone(MemoryStream *stream)
{
    if (stream->hardclone) {
        MemoryStream *clone = stream->hardclone(stream);
        if (clone) {
            _memory_stream_clone(clone, stream);
            return clone;
        }
    }
    return NULL;
}

int memory_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    if (stream->trim) {
        return stream->trim(stream, trimAtStart, trimAtEnd);
    }
    return -1;
}

int memory_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{
    if (stream->expand) {
        return stream->expand(stream, expandAtStart, expandAtEnd);
    }
    return -1;
}

void memory_stream_free(MemoryStream *stream)
{
    if (stream->free) {
        stream->free(stream);
    }
    free(stream);
}

#define COPY_DATA_BUFFER_SIZE 0x4000
int memory_stream_copy_data(MemoryStream *originStream, uint64_t originOffset, MemoryStream *targetStream, uint64_t targetOffset, size_t size)
{
    size_t originSize = memory_stream_get_size(originStream);
    size_t targetSize = memory_stream_get_size(targetStream);
    if (originSize == MEMORY_STREAM_SIZE_INVALID || targetSize == MEMORY_STREAM_SIZE_INVALID) {
        printf("Error: memory_stream_copy_data failed, invalid size detected\n");
        return -1;
    }

    if (originOffset + size > originSize) {
        printf("Error: memory_stream_copy_data failed, originOffset OOB\n");
        return -1;
    }
    if (targetOffset + size > targetSize && !(memory_stream_get_flags(targetStream) | MEMORY_STREAM_FLAG_AUTO_EXPAND)) {
        printf("Error: memory_stream_copy_data failed, targetOffset OOB\n");
        return -1;
    }

    bool backwards = (originStream == targetStream) && (targetOffset > originOffset);

    uint8_t buffer[COPY_DATA_BUFFER_SIZE];
    for (uint32_t copiedSize = 0; copiedSize < size; copiedSize += COPY_DATA_BUFFER_SIZE) {
        uint32_t remainingSize = size - copiedSize;
        uint32_t sizeToCopy = COPY_DATA_BUFFER_SIZE;
        if (remainingSize < sizeToCopy) {
            sizeToCopy = remainingSize;
        }

        uint64_t readOffset = backwards ? ((originOffset + (size - copiedSize)) - sizeToCopy) : (originOffset + copiedSize);
        uint64_t writeOffset = backwards ? ((targetOffset + (size - copiedSize)) - sizeToCopy) : (targetOffset + copiedSize);

        int rr = memory_stream_read(originStream, readOffset, sizeToCopy, buffer);
        if (rr != 0) {
            printf("Error: memory_stream_copy_data failed on memory_stream_read (%d)\n", rr);
            return rr;
        }
        int wr = memory_stream_write(targetStream, writeOffset, sizeToCopy, buffer);
        if (wr != 0) {
            printf("Error: memory_stream_copy_data failed on memory_stream_write (%d)\n", wr);
            return rr;
        }
    }

    return 0;
}

int memory_stream_find_memory(MemoryStream *stream, uint64_t searchStartOffset, uint64_t searchEndOffset, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    __block int r = -1;
    enumerate_range(searchStartOffset, searchEndOffset, alignment, nbytes, ^bool(uint64_t cur) {
        uint8_t buf[nbytes];
        memory_stream_read(stream, cur, nbytes, buf);
        if (!memcmp_masked(buf, bytes, mask, nbytes)) {
            *foundOffsetOut = cur;
            r = 0;
            return false;
        }
        return true;
    });
    return r;
}