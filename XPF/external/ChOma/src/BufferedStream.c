#include "BufferedStream.h"
#include "MemoryStream.h"

#include <stdlib.h>

static int buffered_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd);

static int _buffered_stream_make_own_data(MemoryStream *stream)
{
    BufferedStreamContext *context = stream->context;
    if ((stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) == 0) {
        void *newBuffer = malloc(context->subBufferSize);
        memcpy(newBuffer, context->buffer + context->subBufferStart, context->subBufferSize);
        context->buffer = newBuffer;
        stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;
    }
    return 0;
}

static int buffered_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *outBuf)
{
    BufferedStreamContext *context = stream->context;
    if ((offset + size) > context->subBufferSize) {
        printf("Error: cannot read %zx bytes at %llx, maximum is %zx.\n", size, offset, context->subBufferSize);
        return -1;
    }

    memcpy(outBuf, context->buffer + context->subBufferStart + offset, size);
    return size;
}

static int buffered_stream_write(MemoryStream *stream, uint64_t offset, size_t size, const void *inBuf)
{
    BufferedStreamContext *context = stream->context;

    bool expandAllowed = (stream->flags & MEMORY_STREAM_FLAG_AUTO_EXPAND);
    bool needsExpand = (offset + size) > context->subBufferSize;

    if (needsExpand && !expandAllowed) {
        printf("Error: cannot write %zx bytes at %llx, maximum is %zx.\n", size, offset, context->subBufferSize);
        return -1;
    }

    if ((stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) == 0) {
        int r = _buffered_stream_make_own_data(stream);
        if (r != 0) return r;
    }

    if (needsExpand) {
        buffered_stream_expand(stream, 0, (offset + size) - context->subBufferSize);
    }

    memcpy(context->buffer + context->subBufferStart + offset, inBuf, size);
    return size;
}

static int buffered_stream_get_size(MemoryStream *stream, size_t *sizeOut)
{
    BufferedStreamContext *context = stream->context;
    *sizeOut = context->subBufferSize;
    return 0;
}

static uint8_t *buffered_stream_get_raw_pointer(MemoryStream *stream)
{
    BufferedStreamContext *context = stream->context;
    return &context->buffer[context->subBufferStart];
}

static int buffered_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    BufferedStreamContext *context = stream->context;

    // TODO: bound checks
    context->subBufferStart += trimAtStart;
    context->subBufferSize -= (trimAtEnd + trimAtStart);

    return 0;
}

static int buffered_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{
    BufferedStreamContext *context = stream->context;

    size_t newSize = context->subBufferSize + expandAtStart + expandAtEnd;
    uint8_t *newBuffer = malloc(newSize);
    memset(newBuffer, 0, newSize);
    memcpy(&newBuffer[expandAtStart], &context->buffer[context->subBufferStart], context->subBufferSize);
    if (stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) {
        free(context->buffer);
    }
    context->buffer = newBuffer;
    context->bufferSize = newSize;
    context->subBufferStart = 0;
    context->subBufferSize = newSize;
    stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;

    return 0;
}

static MemoryStream *buffered_stream_softclone(MemoryStream *stream)
{
    MemoryStream* clone = malloc(sizeof(MemoryStream));
    if (!clone) return NULL;
    memset(clone, 0, sizeof(MemoryStream));

    BufferedStreamContext *context = stream->context;
    BufferedStreamContext *contextCopy = malloc(sizeof(BufferedStreamContext));

    contextCopy->buffer = context->buffer;
    contextCopy->bufferSize = context->bufferSize;
    contextCopy->subBufferStart = context->subBufferStart;
    contextCopy->subBufferSize = context->subBufferSize;
    clone->flags = stream->flags & ~(MEMORY_STREAM_FLAG_OWNS_DATA);

    clone->context = contextCopy;
    return clone;
}

static MemoryStream *buffered_stream_hardclone(MemoryStream *stream)
{
    MemoryStream* clone = buffered_stream_softclone(stream);
    if (clone) {
        _buffered_stream_make_own_data(clone);
    }
    return clone;
}

static void buffered_stream_free(MemoryStream *stream)
{
    BufferedStreamContext *context = stream->context;
    if (context->buffer) {
        if (stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) {
            free(context->buffer);
        }
    }
    free(context);
}

static int _buffered_stream_init(MemoryStream *stream)
{
    stream->read = buffered_stream_read;
    stream->write = buffered_stream_write;
    stream->getSize = buffered_stream_get_size;
    stream->getRawPtr = buffered_stream_get_raw_pointer;

    stream->trim = buffered_stream_trim;
    stream->expand = buffered_stream_expand;

    stream->softclone = buffered_stream_softclone;
    stream->hardclone = buffered_stream_hardclone;
    stream->free = buffered_stream_free;

    stream->flags = MEMORY_STREAM_FLAG_MUTABLE;
    return 0;
}

MemoryStream *buffered_stream_init_from_buffer_nocopy(void *buffer, size_t bufferSize, uint32_t flags)
{
    MemoryStream *stream = malloc(sizeof(MemoryStream));
    if (!stream) return NULL;
    memset(stream, 0, sizeof(MemoryStream));

    BufferedStreamContext *context = malloc(sizeof(BufferedStreamContext));
    context->buffer = buffer;
    context->bufferSize = bufferSize;
    context->subBufferStart = 0;
    context->subBufferSize = bufferSize;

    stream->context = context;
    if (_buffered_stream_init(stream) != 0) goto fail;

    if (flags & BUFFERED_STREAM_FLAG_AUTO_EXPAND) {
        stream->flags |= MEMORY_STREAM_FLAG_AUTO_EXPAND;
    }

    return stream;

fail:
    buffered_stream_free(stream);
    return NULL;
}

MemoryStream *buffered_stream_init_from_buffer(void *buffer, size_t bufferSize, uint32_t flags)
{
    void *copy = malloc(bufferSize);
    if (!copy) return NULL;
    memcpy(copy, buffer, bufferSize);
    MemoryStream *stream = buffered_stream_init_from_buffer_nocopy(copy, bufferSize, flags);
    if (stream) {
        stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;
    }
    return stream;
}