#pragma once

#include <cassert>
#include <cstdint>

using std::size_t;

namespace buffer {
    namespace detail {
        constexpr const size_t BUF_SIZE = 0x2000;

        template<typename T, template<typename> typename _Slice>
        struct _basic_slice {
            // ctor
            constexpr inline _basic_slice(T *ptr, size_t len) noexcept: ptr(ptr), len(len){}

            // observer
            constexpr inline T* data() const noexcept { return this->ptr; }
            constexpr inline size_t size() const noexcept { return this->len; }

            // slice this
            constexpr inline _Slice<T> slice() const noexcept {
                return _Slice(this->ptr, this->len);
            }

            // slice (beg, end]
            constexpr inline _Slice<T> slice(size_t beg, size_t end) const noexcept {
                assert(end >= beg);
                assert(this->len >= end - beg);
                return _Slice(this->ptr + beg, end - beg);
            }

            // slice [0, n)
            constexpr inline _Slice<T> slice_until(size_t n) const noexcept {
                return this->slice(0, n);
            }

            // slice [n, -1)
            constexpr inline _Slice<T> slice_from(size_t n) const noexcept {
                return this->slice(n, this->len);
            }

            constexpr inline T& operator[](size_t idx) const noexcept { return this->data()[idx]; }

            constexpr inline _Slice<const std::remove_cv_t<T>> as_const() const noexcept {
                return _Slice<const std::remove_cv_t<T>>(this->ptr, this->len);
            }

            protected:
                T *ptr;
                size_t len;
        };
    }


    using detail::BUF_SIZE;
    using detail::_basic_slice;

    template<typename T>
    struct Slice : _basic_slice<T, Slice> {
        // ctor
        constexpr inline Slice(T* ptr, size_t len) noexcept: _basic_slice<T, Slice>(ptr, len){}
        // allow implicit conversion
        constexpr inline Slice(const Slice<std::remove_cv_t<T>>& rhs)
            noexcept: _basic_slice<T, Slice>(rhs.data(), rhs.size()){}

        // modifier
        constexpr inline void set_ptr(T *ptr) noexcept { this->ptr = ptr; }
        constexpr inline void set_size(size_t n) noexcept { this->len = n; }
        constexpr inline void advance(size_t n) noexcept {
            assert(this->len >= n);
            this->ptr += n; 
            this->len -= n;
        }
    };

    template<typename T>
    struct Buffer : _basic_slice<T, Slice> {    
        // noncopyable ctor
        Buffer(const Buffer&) = delete;
        Buffer& operator=(const Buffer&) = delete;
        constexpr inline Buffer() noexcept: _basic_slice<T, Slice>(new T[BUF_SIZE], BUF_SIZE){}
        constexpr inline Buffer(size_t n) noexcept: _basic_slice<T, Slice>(new T[n], n){}
        constexpr inline Buffer(Buffer&& rhs) noexcept: _basic_slice<T, Slice>(rhs.ptr, rhs.len) {
            rhs.ptr = nullptr; 
        }
        constexpr inline Buffer& operator=(Buffer&& rhs) noexcept {
            this->ptr = rhs.ptr;
            this->len = rhs.len;
            rhs.ptr = nullptr;
            return *this;
        }
        constexpr inline ~Buffer() noexcept { if (this->ptr) delete[] this->ptr; }
    };
}
