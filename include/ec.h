#pragma once

namespace ec {
    enum EC: int {
        Ok = 1,
        MoreData = 100,

        ErrAtyp,
        ErrFqdnLen,
        ErrCRLF,

        ErrRead,
        ErrWrite,

        ErrResolve,
    };
}
