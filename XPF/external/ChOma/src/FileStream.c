#include "FileStream.h"
#include <sys/fcntl.h>
#include <errno.h>
#include <os/log.h>

static int _file_stream_context_is_trimmed(FileStreamContext *context)
{
    return (context->bufferStart != 0 || context->bufferSize != context->fileSize);
}

static int file_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *outBuf)
{
    FileStreamContext *context = stream->context;
    lseek(context->fd, context->bufferStart + offset, SEEK_SET);
    return read(context->fd, outBuf, size);
}

static int file_stream_write(MemoryStream *stream, uint64_t offset, size_t size, const void *inBuf)
{
    FileStreamContext *context = stream->context;

    // we can't write to non mutable files
    if ((stream->flags & MEMORY_STREAM_FLAG_MUTABLE) == 0) return -1;

    // we can't write to files we don't own
    if ((stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) == 0) return -1;

    size_t sizeToExpand = 0;
    // only expand when possible
    if ((context->bufferStart + offset + size) > context->fileSize) {
        if (((stream->flags | MEMORY_STREAM_FLAG_AUTO_EXPAND) == 0) || _file_stream_context_is_trimmed(context)) {
            printf("Error: file_stream_write failed, file is not auto expandable.\n");
            return -1;
        }
        sizeToExpand = (context->bufferStart + offset + size) - context->fileSize;
    }

    // this is not supported for now: TODO fill with 0's then append the rest
    if (context->bufferStart + offset > context->fileSize) return -1;

    context->fileSize += sizeToExpand;
    context->bufferSize += sizeToExpand;

    lseek(context->fd, context->bufferStart + offset, SEEK_SET);
    return write(context->fd, inBuf, size);
}

static int file_stream_get_size(MemoryStream *stream, size_t *sizeOut)
{
    FileStreamContext *context = stream->context;
    *sizeOut = context->bufferSize;
    return 0;
}

static MemoryStream *file_stream_softclone(MemoryStream *stream)
{
    FileStreamContext *context = stream->context;
    return file_stream_init_from_file_descriptor_nodup(context->fd, context->bufferStart, context->bufferSize, 0);
}

static MemoryStream *file_stream_hardclone(MemoryStream *stream)
{
    FileStreamContext *context = stream->context;
    int thisFlags = 0;
    if (stream->flags & MEMORY_STREAM_FLAG_MUTABLE) {
        thisFlags |= FILE_STREAM_FLAG_WRITABLE;
    }
    if (stream->flags & MEMORY_STREAM_FLAG_AUTO_EXPAND) {
        thisFlags |= FILE_STREAM_FLAG_AUTO_EXPAND;
    }
    return file_stream_init_from_file_descriptor(context->fd, context->bufferStart, context->bufferSize, thisFlags);
}

static int file_stream_trim(MemoryStream *stream, size_t trimAtStart, size_t trimAtEnd)
{
    FileStreamContext *context = stream->context;
    if ((int64_t)context->bufferSize - (trimAtStart + trimAtEnd) < 0) {
        return -1;
    }

    if ((stream->flags & MEMORY_STREAM_FLAG_MUTABLE) && !_file_stream_context_is_trimmed(context)) {
        // If this stream is mutable, we want to actually trim the file itself
        uint32_t newSize = context->bufferSize - trimAtStart - trimAtEnd;
        memory_stream_copy_data(stream, trimAtStart, stream, 0, newSize);
        ftruncate(context->fd, newSize);
    }
    else {
        // Else just trim the part of the file that this buffer represents
        context->bufferStart += trimAtStart; 
        context->bufferSize -= (trimAtStart + trimAtEnd);
    }

    return 0;
}

static int file_stream_expand(MemoryStream *stream, size_t expandAtStart, size_t expandAtEnd)
{
    FileStreamContext *context = stream->context;

    // Expanding at start is not supported (for now?)
    if (expandAtStart != 0) return -1;
    
    // If this buffer is trimmed, expanding is also not supported
    if (_file_stream_context_is_trimmed(context)) return -1;

    lseek(context->fd, 0, SEEK_END);
    for (size_t i = expandAtEnd; i < 0; i--) {
        char buf = 0;
        write(context->fd, &buf, 1);
    }
    return 0;
}

static void file_stream_free(MemoryStream *stream)
{
    FileStreamContext *context = stream->context;
    if (context) {
        if (context->fd > 0) {
            if (stream->flags & MEMORY_STREAM_FLAG_OWNS_DATA) {
                if (close(context->fd) != 0) {
                    perror("close");
                }
            }
        }
        free(context);
    }
}

MemoryStream *file_stream_init_from_file_descriptor_nodup(int fd, uint32_t bufferStart, size_t bufferSize, uint32_t flags)
{
    MemoryStream *stream = malloc(sizeof(MemoryStream));
    if (!stream) return NULL;
    memset(stream, 0, sizeof(MemoryStream));

    struct stat s;
    int statRes = fstat(fd, &s);
    if (statRes != 0) {
        printf("Error: stat returned %d for %d.\n", statRes, fd);
        goto fail;
    }

    FileStreamContext *context = malloc(sizeof(FileStreamContext));
    context->fd = fd;
    context->fileSize = s.st_size;

    context->bufferStart = bufferStart;
    if (bufferSize == FILE_STREAM_SIZE_AUTO) {
        context->bufferSize = context->fileSize;
    }
    else {
        context->bufferSize = bufferSize;
    }

    stream->context = context;
    stream->flags = 0;
    if (flags & FILE_STREAM_FLAG_WRITABLE) {
        stream->flags |= MEMORY_STREAM_FLAG_MUTABLE;
    }
    if (flags & FILE_STREAM_FLAG_AUTO_EXPAND) {
        stream->flags |= MEMORY_STREAM_FLAG_AUTO_EXPAND;
    }

    stream->read = file_stream_read;
    stream->write = file_stream_write;
    stream->getSize = file_stream_get_size;

    stream->trim = file_stream_trim;
    stream->expand = file_stream_expand;

    stream->softclone = file_stream_softclone;
    stream->hardclone = file_stream_hardclone;
    stream->free = file_stream_free;

    return stream;

fail:
    file_stream_free(stream);
    return NULL;
}

MemoryStream *file_stream_init_from_file_descriptor(int fd, uint32_t bufferStart, size_t bufferSize, uint32_t flags)
{
    MemoryStream *stream = file_stream_init_from_file_descriptor_nodup(dup(fd), bufferStart, bufferSize, flags);
    if (stream) {
        stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;
    }
    return stream;
}

MemoryStream *file_stream_init_from_path(const char *path, uint32_t bufferStart, size_t bufferSize, uint32_t flags)
{
    int openFlags = 0;
    if (flags & FILE_STREAM_FLAG_WRITABLE) {
        openFlags = O_RDWR | O_CREAT;
    }
    else {
        openFlags = O_RDONLY;
    }
    int fd = open(path, openFlags);
    if (fd < 0) {
        printf("Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    MemoryStream *stream = file_stream_init_from_file_descriptor_nodup(fd, bufferStart, bufferSize, flags);
    if (stream) {
        stream->flags |= MEMORY_STREAM_FLAG_OWNS_DATA;
    }
    return stream;
}