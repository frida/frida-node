#ifndef FRIDANODE_RUNTIME_H
#define FRIDANODE_RUNTIME_H

#include "main_context.h"

namespace frida {

class Runtime {
 public:
  static void Init(MainContext* main_context) {
    main_context_ = main_context;
  }

  static MainContext* GetMainContext() { return main_context_; }

 private:
  static MainContext* main_context_;
};

}

#endif
