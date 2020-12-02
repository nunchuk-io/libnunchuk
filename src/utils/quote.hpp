
#ifndef NUNCHUK_QUOTE_H
#define NUNCHUK_QUOTE_H

#include <iostream>
#include <iomanip>
#include <sstream>

namespace nunchuk {

template <typename CharT>
struct out_quoted {
  const CharT* s;
  CharT delim;
  CharT escape;
};

template <typename CharT>
out_quoted<CharT> quoted(const CharT* s, CharT delim = CharT('"'),
                         CharT escape = CharT('\\')) {
  return {s, delim, escape};
}

template <typename CharT>
out_quoted<CharT> quoted(const std::basic_string<CharT>& s,
                         CharT delim = CharT('"'), CharT escape = CharT('\\')) {
  return {s.c_str(), delim, escape};
}

template <typename CharT>
std::ostream& operator<<(std::ostream& os, const out_quoted<CharT>& q) {
  os << q.delim;
  for (const CharT* p = q.s; *p; p++) {
    if (*p == q.delim || *p == q.escape)
      os << q.escape << *p;
    else
      os << *p;
  }
  return os << q.delim;
}

}  // namespace nunchuk

#endif  // NUNCHUK_QUOTE_H