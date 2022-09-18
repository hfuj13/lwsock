// The MIT License (MIT)
//
// Copyright (C) 2016 hfuj13@gmail.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <regex.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>

namespace lwsock {

constexpr char Version[] = "v1.5.1";
constexpr uint8_t Magic[] = {49, 49, 104, 102, 117, 106, 49, 51};

// [lwsock private]
/// \brief WebSocket(RFC6455) Opcode enum
///
enum class Opcode {
  CONTINUE = 0x0,
  TEXT = 0x1,
  BINARY = 0x2,
  CLOSE = 0x8,
  PING = 0x9,
  PONG = 0xa,
};


/// \brief LWSOCK error codes
///
/// \note Negative value. lwsock-specific error code.
///
enum class LwsockErrc: int32_t {
  NO_ERROR = 0,
  COULD_NOT_OPEN_AVAILABLE_SOCKET = -102,
  SOCKET_CLOSED = -103,
  INVALID_HANDSHAKE = -104,
  FRAME_ERROR = -106,
  INVALID_PARAM = -107,
  INVALID_AF = -108,
  INVALID_MODE = -109,
  BAD_MESSAGE = -110,
  TIMED_OUT = -111,
};

/// \brief Log level
///
enum class LogLevel: int32_t {
  UNDER_LVL = 0,
  VERBOSE,
  DEBUG,
  INFO,
  WARNING,
  ERROR,
  SILENT,
  OVER_LVL
};

// [lwsockprivate]
/// \brief Get emum class value as int
///
/// \param [in] value: Enum class value
/// \retval int value
///
template<typename T> auto as_int(const T value) -> typename std::underlying_type<T>::type
{
  return static_cast<typename std::underlying_type<T>::type>(value);
}

// [lwsockprivate]
/// \brief auto resize sprintf
///
/// \param [in] fmt: format string. so-called printf format
/// \param [in] args: Earch values
/// \retval formatted string
///
template<typename... Args> std::string sprintf(const std::string& fmt, Args... args)
{
  std::string buff; // Used only for dynamic area control.
  int ret = snprintf(&buff[0], buff.capacity(), fmt.c_str(), args...);
  if (ret >= buff.capacity()) {
    buff.reserve(ret+1);
    ret = snprintf(&buff[0], buff.capacity(), fmt.c_str(), args...);
  }
  else if (ret < 0) {
    abort();
  }
  std::string str(buff.c_str());
  return str;
}

// [lwsockprivate]
/// \brief Get now timestamp string. UTC only yet
///
/// \param [in] parenthesis: ture: output with '[' and ']' <br>
///    false : Output with raw
/// \retval Transformed timestamp string. e.g. [2016-12-11T13:24:13.058] or 2016-12-11T13:24:13.058 etc.). the output format is like the ISO8601 (It includes milliseconds)
/// Todo correspond TIME ZONE
///
inline std::string now_timestamp(bool parenthesis)
{
  std::chrono::time_point<std::chrono::system_clock> tp = std::chrono::system_clock::now();
  //std::chrono::nanoseconds nsec_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch());
  std::chrono::milliseconds msec_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
  //std::chrono::milliseconds msec_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(nsec_since_epoch);
  std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(msec_since_epoch);

  std::time_t tt = sec.count();
  std::size_t msec = msec_since_epoch.count() % 1000;
  //std::size_t nsec = nsec_since_epoch.count() % (1000 * 1000); 

  struct tm stm = {0};
  tzset();
  gmtime_r(&tt, &stm);

  std::string timestamp_str = lwsock::sprintf("%04d%02d%02dT%02d:%02d%02d.%03u",
           stm.tm_year+1900, stm.tm_mon+1, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec, msec);
  std::string str;
  if (parenthesis) {
    str += "[" + timestamp_str + "]";
  }
  else {
    str += timestamp_str;
  }
  return str;
}

// [lwsockprivate]
/// \brief get now timestamp string by cloed parenthesis
///
/// \retval Transformed timestamp string. (e.g. [2016-12-11T13:24:13.058])
///
inline std::string now_timestamp()
{
  return now_timestamp(true);
}

// [lwsockprivate]
/// \brief Trim specified characters
///
/// \param [in] str: Target string
/// \param [in] charset: Character set (specified by a string) what you want to delete. e.g. "\n\t"
/// \retval Trimed string
///
inline std::string trim(const std::string& str, const std::string& charset)
{
  std::string::size_type p0 = str.find_first_not_of(charset);
  if (p0 == std::string::npos) {
    p0 = 0;
  }
  std::string::size_type p1 = str.find_last_not_of(charset);

  std::string result = str.substr(p0, p1 - p0 + 1);
  return result;
}

// [lwsockprivate]
/// \brief Trim white spaces
///
/// \param [in] str: Target string
/// \retval Trimed string
///
inline std::string trim(const std::string& str)
{
  return trim(str, " \t\v\r\n");
}


// [lwsockprivate]
/// \brief A Log class
///
class ALog final {
public:

  // [lwsockprivate]
  /// \brief Tracer class
  ///
  /// note It outputs ">>>>" at the beginning when entering, and outputs "<<<<" at the beginning when exiting.
  ///
  class Tracer final {
  public:

    // [lwsockprivate]
    /// \brief Constructor
    ///
    Tracer() = delete;
    Tracer(const Tracer&) = delete;
    Tracer(Tracer&&) = default;
    Tracer(const std::string& str)
    : Tracer(LogLevel::DEBUG, str)
    {}
    Tracer(LogLevel loglevel, const std::string& str)
    : loglevel_(loglevel), oss_(str)
    {
      log_(loglevel_) << ">>>> " << oss_.str() << std::endl;
    }

    // [lwsockprivate]
    /// \brief Destructor
    ///
    ~Tracer()
    {
      log_(loglevel_) << "<<<< " << oss_.str() << std::endl;
    }

    // [lwsockprivate]
    /// \brief operator=
    ///
    Tracer& operator=(const Tracer&) = delete;
    Tracer& operator=(Tracer&&) = default;

    template<typename T> friend std::ostream& operator<<(Tracer& tracer, const T& rhs);

    // [lwsockprivate]
    /// \brief Get a log string
    ///
    /// \retval A log string
    ///
    std::string str()
    {
      return oss_.str();
    }

    // [lwsockprivate]
    /// \brief Clear a log string
    ///
    /// \retval Reference of *this
    ///
    Tracer& clear()
    {
      oss_.str("");
      return *this;
    }

  private:
    ALog& log_ = ALog::get_instance();
    LogLevel loglevel_ = LogLevel::DEBUG;
    std::ostringstream oss_;
  };

  // [lwsockprivate]
  /// \brief operator==
  ///
  /// \param [in] rhs: Alog instance
  /// \retval Boolean value
  ///
  bool operator==(const ALog& rhs) const
  {
    return &rhs == this || (rhs.level_ == level_ && rhs.ost_ == ost_);
  }

  // [lwsockprivate]
  /// \brief operator!=
  ///
  /// \param [in] rhs: Alog instance
  /// \retval Boolean value
  ///
  bool operator!=(const ALog& rhs) const
  {
    return (rhs.level_ != level_ || rhs.ost_ != ost_);
  }

  static ALog& get_instance()
  {
    return get_instance(nullptr);
  }
  static ALog& get_instance(std::ostream& ost)
  {
    return get_instance(&ost);
  }

  // [lwsockprivate]
  /// \brief Output a verbose level log
  ///
  /// Output a log message when the log level is VERBOSE or lower.
  ///
  /// \retval
  ///
  std::ostream& verbose()
  {
    return (*this)(LogLevel::VERBOSE) << "[V]";
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& verbose(const std::string& fmt, Args... args)
  {
    return verbose() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  /// Output a log message when the log level setting is DEBUG or lower.
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \retval
  ///
  std::ostream& debug()
  {
    return (*this)(LogLevel::DEBUG) << "[D]";
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& debug(const std::string& fmt, Args... args)
  {
    return debug() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  /// Output a log message when the log level setting is INFO or lower.
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \retval
  ///
  std::ostream& info()
  {
    return (*this)(LogLevel::INFO) << "[I]";
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& info(const std::string& fmt, Args... args)
  {
    return info() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  /// Output a log message when the log level setting is WARNING or lower.
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \retval
  ///
  std::ostream& warning()
  {
    return (*this)(LogLevel::WARNING) << "[W]";
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& warning(const std::string& fmt, Args... args)
  {
    return warning() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  /// Output a log message when the log level setting is ERROR or lower.
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \retval
  ///
  std::ostream& error()
  {
    return (*this)(LogLevel::ERROR) << "[E]";
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& error(const std::string& fmt, Args... args)
  {
    return error() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  // Force output no matter what the log level setting is.
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \retval
  ///
  std::ostream& force()
  {
    return (*this)();
  }
  // [lwsockprivate]
  /// \brief
  ///
  ///
  ///
  /// \param [in] fmt: Format string. printf() like. e.g. "%s %d\n"
  /// \retval
  ///
  template<typename... Args> std::ostream& force(const std::string& fmt, Args... args)
  {
    return force() << lwsock::sprintf(fmt, args...) << std::flush;
  }

  template<typename T> friend std::ostream& operator<<(ALog& log, const T& rhs);

  /// Set log level
  ALog& level(LogLevel lvl)
  {
    assert(LogLevel::UNDER_LVL <= lvl && lvl <= LogLevel::OVER_LVL);
    level_ = lvl;
    return *this;
  }

  /// Get log level
  LogLevel level()
  {
    return level_;
  }

  /// Set ostream reference
  ALog& ostream(std::ostream& ost)
  {
    ost_ = &ost;
    return *this;
  }

private:
  ALog() = default;
  ALog& operator=(const ALog&) = delete;

  /// Output the timestamp and the thread id
  std::ostream& output()
  {
    return (*ost_) << now_timestamp() << "[thd:" << std::this_thread::get_id() << "] ";
  }

  /// Output the timestamp and the thread id
  std::ostream& operator()()
  {
    return output();
  }

  /// Output a log message when lvl grater equal the log setting.
  std::ostream& operator()(LogLevel lvl)
  {
    return lvl >= level_ ? output() : null_ost_;
  }

  static ALog& get_instance(std::ostream* ost)
  {
    static ALog log;
    if (ost != nullptr) {
      log.ost_ = ost;
    }
    return log;
  }

  std::ostream null_ost_{nullptr}; // that is /dev/null like
  LogLevel level_ = LogLevel::SILENT;
  std::ostream* ost_ = &null_ost_;
};

// [lwsockprivate]
template<typename T> std::ostream& operator<<(ALog& log, const T& rhs)
{
  return (*log.ost_) << rhs;
}

// [lwsockprivate]
template<typename T> std::ostream& operator<<(ALog::Tracer& tracer, const T& rhs)
{
  return tracer.oss_ << rhs;
}

/// \brief Error class
///
/// Manage the error code, line number and a error message.
///
class Error final {
public:
  Error() = delete;
  Error(const Error&) = default;
  Error(Error&&) = default;

  /// \brief Constructer
  ///
  /// \param [in] errcode: Error code
  /// \param [in] line: Line number
  /// \param [in] what_arg: Error message
  Error(int errcode, int line, const std::string& what_arg)
  : errcode_(errcode), line_(line)
  {
    std::ostringstream oss;
    if (line_ > 0) {
      oss << "line:" << line_ << ". " << "errcode=" << errcode_ << ". " << what_arg;
      what_ = oss.str();
    }
    else {
      oss << "errcode=" << errcode_ << ". " << what_arg;
      what_ = oss.str();
    }
    ALog& log = ALog::get_instance();
    log.error() << what_ << std::endl;
  }

  explicit Error(int errcode, int line)
  : Error(errcode, line, "")
  {}
  Error(int errcode, const std::string& what_arg)
  : Error(errcode, 0, what_arg)
  {}
  explicit Error(int errcode)
  : Error(errcode, 0, "")
  {}

  ~Error() = default;

  /// \brief Get error code
  ///
  /// \retval Error code. errno(3), getaddrinfo(3), regcomp(3), lwsock Errcode.
  int code()
  {
    return errcode_;
  }

  /// \brief Set the prefix to be attached to the cause message.
  ///
  void prefix(const std::string& prefix)
  {
    what_ = prefix + what_;
  }

  /// \brief Get a reason message.
  ///
  /// \retval Const pointer to the reason message.
  const char* what() const
  {
    return what_.c_str();
  }

private:
  int errcode_ = 0;
  int line_ = 0; // The line number when the error occurred
  std::string what_; // The reason message
};

/// \brief An exception class for CRegex
///
class CRegexException final: public std::exception {
public:
  CRegexException() = delete;
  CRegexException(const CRegexException&) = default;
  CRegexException(CRegexException&&) = default;
  CRegexException(const Error& error)
  : error_(error)
  {}
  CRegexException(Error&& error)
  : error_(error)
  {}
  CRegexException& operator=(const CRegexException&) = default;
  CRegexException& operator=(CRegexException&&) = default;

  ~CRegexException() = default;

  /// \brief Get a reason message.
  ///
  /// \retval Const pointer to the reason message.
  const char* what() const noexcept override
  {
    error_.prefix("CRegexException: ");
    return error_.what();
  }

  /// \brief Get A code number (error code etc.)
  ///
  /// \retavl A code number
  virtual int code()
  {
    return error_.code();
  }
private:
  mutable Error error_;
};

/// \brief An exception class for getaddrinfo(3)
///
class GetaddrinfoException final: public std::exception {
public:
  GetaddrinfoException() = delete;
  GetaddrinfoException(const GetaddrinfoException&) = default;
  GetaddrinfoException(GetaddrinfoException&&) = default;
  GetaddrinfoException(const Error& error)
  : error_(error)
  {}
  GetaddrinfoException(Error&& error)
  : error_(error)
  {}
  GetaddrinfoException& operator=(const GetaddrinfoException&) = default;
  GetaddrinfoException& operator=(GetaddrinfoException&&) = default;

  ~GetaddrinfoException() = default;

  /// \brief Get a reason message.
  ///
  /// \retval Const pointer to the reason message.
  const char* what() const noexcept override
  {
    error_.prefix("GetaddrinfoException: ");
    return error_.what();
  }

  /// \brief Get A code number (error code etc.)
  ///
  /// \retavl A code number
  virtual int code()
  {
    return error_.code();
  }
private:
  mutable Error error_;
};

/// \brief An exception class for LWSOCK
///
class LwsockException final: public std::exception {
public:
  LwsockException() = delete;
  LwsockException(const LwsockException&) = default;
  LwsockException(LwsockException&&) = default;
  LwsockException(const Error& error)
  : error_(error)
  {}
  LwsockException(Error&& error)
  : error_(error)
  {}
  LwsockException& operator=(const LwsockException&) = default;
  LwsockException& operator=(LwsockException&&) = default;

  ~LwsockException() = default;

  /// \brief Get a reason message.
  ///
  /// \retval Const pointer to the reason message.
  const char* what() const noexcept override
  {
    error_.prefix("LwsockException: ");
    return error_.what();
  }

  /// \brief Get A code number (error code etc.)
  ///
  /// \retavl A code number
  virtual int code()
  {
    return error_.code();
  }
private:
  mutable Error error_;
};

/// \brief An exception class for System error
///
class SystemErrorException final: public std::exception {
public:
  SystemErrorException() = delete;
  SystemErrorException(const SystemErrorException&) = default;
  SystemErrorException(SystemErrorException&&) = default;
  SystemErrorException(const Error& error)
  : error_(error)
  {}
  SystemErrorException(Error&& error)
  : error_(error)
  {}
  SystemErrorException& operator=(const SystemErrorException&) = default;
  SystemErrorException& operator=(SystemErrorException&&) = default;

  ~SystemErrorException() = default;

  /// \brief Get a reason message.
  ///
  /// \retval Const pointer to the reason message.
  const char* what() const noexcept override
  {
    error_.prefix("SystemErrorException: ");
    return error_.what();
  }

  /// \brief Get A code number (error code etc.)
  ///
  /// \retavl A code number
  virtual int code()
  {
    return error_.code();
  }
private:
  mutable Error error_;
};

/// \brief regex(3) wrapper class
///
/// regex(3) wrapper class. Because std::regex may not work correctly on some android versions.
class CRegex final {
public:
  CRegex() = delete;
  CRegex(const CRegex&) = default;
  CRegex(CRegex&) = default;
  CRegex& operator=(const CRegex&) = default;
  CRegex& operator=(CRegex&) = default;

  /// \brief Constructor
  ///
  /// \exception CRegexException
  CRegex(const std::string& re, size_t nmatch)
  : nmatch_(nmatch)
  {
    assert(nmatch > 0);
    ALog& log = ALog::get_instance();
    log.debug() << "CRegex(re=\"" << re << "\", nmatch=" << nmatch << ')' << std::endl;

    int err = regcomp(&regbuff_, re.c_str(), REG_EXTENDED);
    if (err != 0) {
      std::ostringstream oss;
      char errbuf[256] = {0};
      regerror(err, &regbuff_, errbuf, sizeof errbuf);
      oss << "CRegex(re=\"" << re << "\", nmatch=" << nmatch << ") " << errbuf;
      throw CRegexException(Error(err, oss.str()));
    }
  }

  /// \brief Destructor
  ///
  ~CRegex()
  {
    regfree(&regbuff_);
  }

  /// \brief Execute regex
  ///
  /// \param [in] src: Target string for regex
  /// \retval Extracted strings vector. if empty then no matched
  std::vector<std::string> exec(const std::string& src)
  {
    assert(nmatch_ > 0);
    std::vector<std::string> matched;
    std::vector<regmatch_t> match(nmatch_, {-1, -1});
    int err = regexec(&regbuff_, src.c_str(), match.size(), &match[0], 0);
    if (err != 0) {
      return matched;
    }
    for (auto& elm : match) {
      int start = elm.rm_so;
      int end = elm.rm_eo;
      if (start == -1 || end == -1) {
        continue;
      }
      std::string str(std::begin(src)+start, std::begin(src)+end);
      matched.push_back(str);
    }
    return matched;
  }
private:
  regex_t regbuff_{};
  size_t nmatch_ = 0;
};

// [lwsockprivate]
/// \brief Callee info class. (func name, params etc.)
///
/// Callee info
///
class Callee final {
public:
  /// \brief Constructor
  ///
  /// \param [in] func_name: Function or Method name
  ///
  Callee(const std::string& func_name)
  : func_name_(func_name)
  {
    oss_ << func_name << "()";
  }
  Callee(std::string&& func_name)
  : func_name_(func_name)
  {
    oss_ << func_name << "()";
  }

  /// \brief Constructor
  ///
  Callee(const Callee&) = default;
  Callee(Callee&&) = default;

  /// \brief Constructor
  ///
  /// \param [in] func_name: Function or Method name
  /// \param [in] params: Parameters
  ///
  Callee(const std::string& func_name, const std::string& params)
  : func_name_(func_name)
  , params_(params)
  {
    oss_ << func_name << params;
  }
  Callee(std::string&& func_name, std::string&& params)
  : func_name_(func_name)
  , params_(params)
  {
    oss_ << func_name << params;
  }
  template<typename... Args> Callee(const std::string& func_name, const std::string& fmt, Args... args)
  : Callee(Callee::sprintf(func_name, fmt, args...))
  {}
//  template<typename... Args> Callee(const std::string& func_name, const std::string& fmt, Args... args)
//  : Callee(Callee::sprintf(func_name, fmt, args...))
//  {}

  /// \brief Destructor
  ///
  ~Callee() = default;

  /// \brief operator=
  ///
  Callee& operator=(const Callee&) = default;
  Callee& operator=(Callee&&) = default;

  static Callee sprintf(const std::string& func_name)
  {
    return Callee(func_name);
  }

  template<typename... Args> static Callee sprintf(const std::string& func_name, const std::string& fmt, Args... args)
  {
    std::string params = lwsock::sprintf(fmt, args...);
    return Callee(func_name, params);
  }

  template<typename T> friend Callee& operator<<(Callee& callee, const T& rhs);

  std::string str()
  {
    return oss_.str();
  }

private:
  Callee() = default;

  std::string func_name_;
  std::string params_;
  std::ostringstream oss_;

};

template<typename T> Callee& operator<<(Callee& callee, const T& rhs)
{
  callee.oss_ << rhs;
  return callee;
}

// [lwsockprivate]
/// \brief Base64 class
///
class Base64 final {
public:
  Base64() = delete;
  ~Base64() = delete;
  static std::string prefix()
  {
    return "Base64::";
  }

  /// \brief Base64 encoder
  ///
  /// \param [in] src_data: Array or vector
  /// \param [in] src_data_sz: *src_data size. Bytes
  /// \retval Base64 encoded string
  /// note This referred the https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c
  ///
  static std::string encode(const void* src_data, int src_data_sz)
  {
    assert(src_data_sz >= 0);
    std::string dst;
    const uint8_t* src = static_cast<const uint8_t*>(src_data);
    int idx = 0;

    for (; idx < src_data_sz - 2; idx += 3) {
      dst += b64chs[(src[idx] >> 2) & 0x3F];
      dst += b64chs[((src[idx] & 0x3) << 4) | ((src[idx + 1] & 0xF0) >> 4)];
      dst += b64chs[((src[idx + 1] & 0xF) << 2) | ((src[idx + 2] & 0xC0) >> 6)];
      dst += b64chs[src[idx + 2] & 0x3F];
    }
    if (idx < src_data_sz) {
      dst += b64chs[(src[idx] >> 2) & 0x3F];
      if (idx == (src_data_sz - 1)) {
          dst += b64chs[((src[idx] & 0x3) << 4)];
          dst += '=';
      }
      else {
          dst += b64chs[((src[idx] & 0x3) << 4) | ((src[idx + 1] & 0xF0) >> 4)];
          dst += b64chs[((src[idx + 1] & 0xF) << 2)];
      }
      dst += '=';
    }

    return dst;
  }
  static std::string encode(const std::vector<uint8_t>& src_data)
  {
    std::string dst = encode(&src_data[0], src_data.size());
    return dst;
  }
  template<std::size_t N> static std::string encode(const std::array<uint8_t, N>& src_data)
  {
    std::string dst = encode(&src_data[0], N);
    return dst;
  }

  /// \brief Base64 decoder
  ///
  /// \param [in] src: Base64 encoded string
  /// \retval Base64 decoded data
  /// \exception LwsockException
  static std::vector<uint8_t> decode(const std::string& src)
  {
    Callee callee(prefix() + __func__, "(src=\"%s\")", src.c_str());

    if (src.size() % 4 != 0) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " src.size()=" << src.size() << " is illegal.";
      throw LwsockException(Error(err, oss.str()));
    }
    constexpr int BLOCK_SZ = 4;
    std::vector<uint8_t> dst;
    for (size_t i = 0; i < src.size(); i += BLOCK_SZ) {
      const char* ptr = &src[i];
      std::array<uint8_t, 3> tmp;
      uint8_t value[BLOCK_SZ] = {0};
      int j = 0;
      for (; j < BLOCK_SZ; ++j) {
        if (std::isupper(ptr[j])) {
          value[j] = ptr[j] - 65;
        }
        else if (std::islower(ptr[j])) {
          value[j] = ptr[j] - 71;
        }
        else if (std::isdigit(ptr[j])) {
          value[j] = ptr[j] + 4;
        }
        else if (ptr[j] == '+') {
          value[j] = ptr[j] + 19;
        }
        else if (ptr[j] == '/') {
          value[j] = ptr[j] + 16;
        }
        else if (ptr[j] == '=') {
          break;
        }
        else {
          int err = as_int(LwsockErrc::INVALID_PARAM);
          std::ostringstream oss;
          char ch = ptr[j];
          oss << callee.str() << " illegal char='" << ch << '\'';
          throw LwsockException(Error(err, oss.str()));
        }
      }
      tmp[0] = value[0] << 2 | value[1] >> 4;
      tmp[1] = value[1] << 4 | value[2] >> 2;
      tmp[2] = value[2] << 6 | value[3];
      std::copy(std::begin(tmp), std::begin(tmp) + j - 1, std::back_inserter(dst));
    }
    return dst;
  }

private:
  static constexpr char b64chs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
};

/// \brief Sha1 class
///
/// This referred the RFC3174 Section 7.
class Sha1 final {
public:
  static constexpr int SHA1_HASH_SIZE = 20;
  static constexpr int MESSAGE_BLOCK_SIZE = 64; // 512-bit message blocks
  enum {
      shaSuccess = 0,
      shaNull,            /* Null pointer parameter */
      shaInputTooLong,    /* input data too long */
      shaStateError       /* called Input after Result */
  };
  Sha1() = delete;
  Sha1(const Sha1&) = delete;
  Sha1(Sha1&&) = delete;

  // This will hold context information for the SHA-1 hashing operation
  class Context_t final {
  public:
    Context_t()
    {
      Intermediate_Hash[0]   = 0x67452301;
      Intermediate_Hash[1]   = 0xEFCDAB89;
      Intermediate_Hash[2]   = 0x98BADCFE;
      Intermediate_Hash[3]   = 0x10325476;
      Intermediate_Hash[4]   = 0xC3D2E1F0;
    }
    Context_t(const Context_t&) = default;
    Context_t(Context_t&&) = default;
    Context_t& operator=(const Context_t&) = default;
    Context_t& operator=(Context_t&&) = default;

    ~Context_t() = default;

    uint32_t Intermediate_Hash[SHA1_HASH_SIZE / 4] = {0}; /* Message Digest  */
    uint32_t Length_Low = 0;  /* Message length in bits */
    uint32_t Length_High = 0; /* Message length in bits */
    int_least16_t Message_Block_Index = 0;
    uint8_t Message_Block[MESSAGE_BLOCK_SIZE] = {0}; /* 512-bit message blocks */
  };

  static int32_t Input(Context_t& dst, const void* message_array, int length)
  {
    assert(message_array != nullptr);
    assert(length >= 0);

    const uint8_t* p = static_cast<const uint8_t*>(message_array);

    for (int i = 0; length > 0; --length, ++i) {
      dst.Message_Block[dst.Message_Block_Index++] = (p[i] & 0xFF);
      dst.Length_Low += 8;
      if (dst.Length_Low == 0) {
        dst.Length_High++;
        if (dst.Length_High == 0) {
          /* Message is too long */
          return EMSGSIZE;
        }
      }

      if (dst.Message_Block_Index == MESSAGE_BLOCK_SIZE) {
          dst = SHA1ProcessMessageBlock(dst);
      }
    }

    return 0;;
  }

  static int32_t Result(uint8_t* Message_Digest, size_t sz, const Context_t& context)
  {
    assert(Message_Digest != nullptr);
    assert(sz == SHA1_HASH_SIZE);

    Context_t ctx = SHA1PadMessage(context);
    for (int i = 0; i < MESSAGE_BLOCK_SIZE; ++i) {
      /* message may be sensitive, clear it out */
      ctx.Message_Block[i] = 0;
    }

    // and clear length
    ctx.Length_Low = 0;
    ctx.Length_High = 0;

    for (size_t i = 0; i < sz; ++i) {
      Message_Digest[i] = ctx.Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
    }

    return 0;
  }
#if 0
  static int32_t Result(std::array<uint8_t, SHA1_HASH_SIZE>& message_digest, const Context_t& context)
  {
    Context_t ctx = SHA1PadMessage(context);
    for (int i = 0; i < MESSAGE_BLOCK_SIZE; ++i) {
      /* message may be sensitive, clear it out */
      ctx.Message_Block[i] = 0;
    }

    // and clear length
    ctx.Length_Low = 0;
    ctx.Length_High = 0;

    for (size_t i = 0; i < sz; ++i) {
      Message_Digest[i] = ctx.Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
    }

    return 0;
  }
#endif

private:
  // SHA1ProcessMessageBlock
  // Description:
  //     This function will process the next 512 bits of the message
  //     stored in the Message_Block array.
  // Comments:
  //     Many of the variable names in this code, especially the
  //     single character names, were used because those were the
  //     names used in the publication.
  static Context_t SHA1ProcessMessageBlock(const Context_t& context)
  {
    Context_t ctx(context);
    constexpr uint32_t K[] = { // Constants defined in SHA-1
      0x5A827999,
      0x6ED9EBA1,
      0x8F1BBCDC,
      0xCA62C1D6
    };
    int      t = 0; // Loop counter
    uint32_t temp = 0; // Temporary word value
    uint32_t W[80] = {0}; // Word sequence
    uint32_t A = 0, B = 0, C = 0, D = 0, E = 0; // Word buffers

    // Initialize the first 16 words in the array W
    for (t = 0; t < 16; ++t) {
        W[t] = ctx.Message_Block[t * 4] << 24;
        W[t] |= ctx.Message_Block[t * 4 + 1] << 16;
        W[t] |= ctx.Message_Block[t * 4 + 2] << 8;
        W[t] |= ctx.Message_Block[t * 4 + 3];
    }
    for (t = 16; t < 80; ++t) {
       W[t] = SHA1CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    A = ctx.Intermediate_Hash[0];
    B = ctx.Intermediate_Hash[1];
    C = ctx.Intermediate_Hash[2];
    D = ctx.Intermediate_Hash[3];
    E = ctx.Intermediate_Hash[4];
    for (t = 0; t < 20; ++t) {
        temp =  SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }
    for (t = 20; t < 40; ++t) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; ++t) {
        temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; ++t) {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    ctx.Intermediate_Hash[0] += A;
    ctx.Intermediate_Hash[1] += B;
    ctx.Intermediate_Hash[2] += C;
    ctx.Intermediate_Hash[3] += D;
    ctx.Intermediate_Hash[4] += E;
    ctx.Message_Block_Index = 0;

    return ctx;
  }
  /*
   *  SHA1PadMessage
   *
   *  Description:
   *      According to the standard, the message must be padded to an even
   *      512 bits.  The first padding bit must be a '1'.  The last 64
   *      bits represent the length of the original message.  All bits in
   *      between should be 0.  This function will pad the message
   *      according to those rules by filling the Message_Block array
   *      accordingly.  It will also call the ProcessMessageBlock function
   *      provided appropriately.  When it returns, it can be assumed that
   *      the message digest has been computed.
   *
   *  Parameters:
   *      context: [in/out]
   *          The context to pad
   *      ProcessMessageBlock: [in]
   *          The appropriate SHA*ProcessMessageBlock function
   *  Returns:
   *      Nothing.
   *
   */
  static Context_t SHA1PadMessage(const Context_t& context)
  {
    Context_t ctx(context);

    //  Check to see if the current message block is too small to hold
    //  the initial padding bits and length.  If so, we will pad the
    //  block, process it, and then continue padding into a second
    //  block.
    if (ctx.Message_Block_Index > 55) {
        ctx.Message_Block[ctx.Message_Block_Index++] = 0x80;
        while (ctx.Message_Block_Index < MESSAGE_BLOCK_SIZE) {
            ctx.Message_Block[ctx.Message_Block_Index++] = 0;
        }

        ctx = SHA1ProcessMessageBlock(ctx);

        while (ctx.Message_Block_Index < 56) {
            ctx.Message_Block[ctx.Message_Block_Index++] = 0;
        }
    }
    else {
        ctx.Message_Block[ctx.Message_Block_Index++] = 0x80;
        while (ctx.Message_Block_Index < 56) {
            ctx.Message_Block[ctx.Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    ctx.Message_Block[56] = ctx.Length_High >> 24;
    ctx.Message_Block[57] = ctx.Length_High >> 16;
    ctx.Message_Block[58] = ctx.Length_High >> 8;
    ctx.Message_Block[59] = ctx.Length_High;
    ctx.Message_Block[60] = ctx.Length_Low >> 24;
    ctx.Message_Block[61] = ctx.Length_Low >> 16;
    ctx.Message_Block[62] = ctx.Length_Low >> 8;
    ctx.Message_Block[63] = ctx.Length_Low;

    ctx = SHA1ProcessMessageBlock(ctx);
    return ctx;
  }

  // Define the SHA1 circular left shift macro
  static uint32_t SHA1CircularShift(uint32_t bits, uint32_t word)
  {
    return (((word) << (bits)) | ((word) >> (32-(bits))));
  }
};

/// \brief Check it is numerichost
///
/// \param [in] host: Host
/// \retval true it is ipaddress (numeric host)
/// \retval false it is hostname (e.g. FQDN)
/// \exception CRegexException
inline bool is_numerichost(const std::string& host)
{
  std::string trimed_host(trim(host, "[]"));
  uint8_t tmp[sizeof(struct in6_addr)] = {0};
  int ret = inet_pton(AF_INET, trimed_host.c_str(), tmp);
  if (ret != 1) {
    ret = inet_pton(AF_INET6, trimed_host.c_str(), tmp);
  }
  return ret == 1;
}

/// \brief Split into host_port part and path_query part
///
/// \param [in] uri: Uri
/// \retval pair::first: host_port <br>
///         pair::second: path_query
/// \exception CRegexException
/// \exception LwsockException
inline std::pair<std::string, std::string> split_hostport_pathquery(const std::string& uri)
{
  Callee callee(__func__, "(uri=\"%s\")", uri.c_str());
  ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

  std::string re = R"(^ws://([][0-9A-Za-z\.:\-]+)(/.*)?)";
  size_t nmatch = 3+1;

  std::pair<std::string, std::string> hostport_pathquery;

  CRegex regex(re, nmatch);
  auto result = regex.exec(uri);
  switch (result.size()) {
  case 3:
    hostport_pathquery.second = result[2];
    //[[fallthrough]];
  case 2:
    hostport_pathquery.first = result[1];
    break;
  default:
    {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid uri.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    break;
  }

  ALog& log = ALog::get_instance();
  log.debug() << "    hostport=\"" << hostport_pathquery.first << "\"\n";
  log.debug() << "    pathquery=\"" << hostport_pathquery.second << '\"'<< std::endl;

  tracer.clear() << __func__ << "(...)";

  return hostport_pathquery;
}

/// \brief Split into path part and query part
///
/// \param [in] path_query: Path and query string. (e.g. /aaa/bbb/ccc?i=1&j=2)
/// \retval pair::first: Path <br>
///         pair::second: Query
/// \exception CRegexException
/// \exception LwsockException
inline std::pair<std::string, std::string> split_path_query(const std::string& path_query_str)
{
  Callee callee(__func__, "(path_query_str=\"%s\")", path_query_str.c_str());
  ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

  std::string re = R"((/?[^? ]*)(\?[^ ]*)?)";
  size_t nmatch = 3+1;

  std::pair<std::string, std::string> path_query;
  CRegex regex(re, nmatch);
  auto result = regex.exec(path_query_str);
  if (result.size() == 0)
  { return path_query; }
  switch (result.size()) {
  case 3:
    path_query.second = result[2];
    //[[fallthrough]];
  case 2:
    path_query.first = result[1][0] != '/' ? "/" + result[1] : result[1];
    break;
  default:
    { int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid path_query_str.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    break;
  }

  ALog& log = ALog::get_instance();
  log.debug() << "    path=\"" << path_query.first << "\"\n";
  log.debug() << "    query=\"" << path_query.second << '\"'<< std::endl;

  tracer.clear() << __func__ << "(...)";
  return path_query;
}

/// \brief Split into host part and port number part.
///
/// \param [in] host_port_str: Host and port string. (e.g. aaa.bbb.ccc:12000, 192.168.0.1:12000 etc.)
/// \retval pair::first: Host <br>
///         pair::second: Port number
/// \exception CRegexException
/// \exception LwsockException
inline std::pair<std::string, std::string> split_host_port(const std::string& host_port_str)
{
  Callee callee(__func__, "(host_port_str=\"%s\")", host_port_str.c_str());
  ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

  std::pair<std::string, std::string> host_port;

  std::string anyaddr = "[::0]:0.0.0.0";
  if (host_port_str.find(anyaddr) != std::string::npos) {
    host_port.first = ""; // anyaddr node
    if (host_port_str.length() > anyaddr.length()) {
      host_port.second = host_port_str.substr(anyaddr.length()+1);
    }
  }
  else if (host_port_str.find("[") != std::string::npos) { // maybe host part is numeric IPv6
    std::string re = R"((\[.*\])(:[0-9]{1,5})?)";
    size_t nmatch = 3+1;
    CRegex regex(re, nmatch);
    std::vector<std::string> tmp = regex.exec(host_port_str);
    switch (tmp.size()) {
    case 3:
      host_port.second = tmp[2].at(0) == ':' ? tmp[2].substr(1) : tmp[2];
      //[[fallthrough]];
    case 2:
      host_port.first = trim(tmp[1], "[]");
      break;
    default:
      {
        int err = as_int(LwsockErrc::INVALID_PARAM);
        std::ostringstream oss;
        oss << callee.str() << " invalid host_port_str.";
        throw LwsockException(Error(err, __LINE__, oss.str()));
      }
      break;
    }
  }
  else {
    // There aren't collons.
    //   hostname
    //   IPv4
    // There is one collon.
    //   hostname:port
    //   IPv4:port
    // There are two or more collons.
    //   IPv6
    int cnt = std::count(std::begin(host_port_str), std::end(host_port_str), ':');
    switch (cnt) {
    case 0:
      host_port.first = host_port_str;
      break;
    case 1:
      {
        std::string::size_type pos = host_port_str.find_last_of(':');
        host_port.first = host_port_str.substr(0, pos);
        host_port.second = host_port_str.substr(pos+1);
      }
      break;
    default:
      host_port.first = host_port_str;
      break;
    }
  }

  ALog& log = ALog::get_instance();
  log.debug() << "    host=\"" << host_port.first << "\"\n";
  log.debug() << "    port=\"" << host_port.second << '\"'<< std::endl;

  tracer.clear() << __func__ << "()";
  return host_port;
}


//  RFC6455 Section 5.2
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

// [lwsockprivate]
/// \brief AHead class
///
/// A part of the Header class. fin,rsv1,rsv2,rsv3,opcode,payload_len
/// Little Endian is assumed
class AHead final {
public:
  AHead() = default;
  AHead(const AHead&) = default;
  AHead(AHead&&) = default;
  explicit AHead(uint16_t data) // data is network byte order
  : data_(data) {}

  ~AHead() = default;

  AHead& operator=(const AHead&) = default;
  AHead& operator=(AHead&&) = default;

  /// \brief Get raw data
  ///
  /// \retval Raw data
  uint16_t data()
  {
    return data_;
  }

  /// \brief Get the pointer for data
  ///
  /// \retval The pointer for data
  uint16_t* data_ptr()
  {
    return &data_;
  }

  /// \brief Get size of data
  ///
  /// \retval Size of data
  size_t size()
  {
    return sizeof data_;
  }

  /// \brief Set FIN bit
  ///
  /// \retval Reference of *this 
  AHead& fin_set()
  {
    return fin(1);
  }

  /// \brief Reset FIN bit
  ///
  /// \retval Reference of *this 
  AHead& fin_reset()
  {
    return fin(0);
  }

  /// \brief Get FIN bit
  ///
  /// \retval FIN bit value. 0 or 1
  int fin()
  {
    return (data_ & 0x0080) >> 7;
  }

  /// \brief Set RSV1 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv1_set()
  {
    return rsv1(1);
  }

  /// \brief Reset RSV1 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv1_reset()
  {
    return rsv1(0);
  }

  /// \brief Get RSV1 bit
  ///
  /// \retval RSV1 bit value
  int rsv1()
  {
    return (data_ & 0x0040) >> 6;
  }

  /// \brief Set RSV2 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv2_set()
  {
    return rsv2(1);
  }

  /// \brief Reset RSV2 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv2_reset()
  {
    return rsv2(0);
  }

  /// \brief Get RSV2 bit
  ///
  /// \retval RSV2 bit value
  int rsv2()
  {
    return (data_ & 0x0020) >> 5;
  }

  /// \brief Set RSV3 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv3_set()
  {
    return rsv3(1);
  }
  /// \brief Reset RSV3 bit
  ///
  /// \retval Reference of *this 
  AHead& rsv3_reset()
  {
    return rsv3(0);
  }

  /// \brief Get RSV3 bit
  ///
  /// \retval rsv3 bit value
  int rsv3()
  {
    return (data_ & 0x0010) >> 4;
  }

  /// \brief Set opcode
  ///
  /// \param [in] val: opcode value
  /// \retval Reference of *this 
  AHead& opcode(Opcode val)
  {
    data_ = (data_ & 0xfff0) | static_cast<uint8_t>(val);
    return *this;
  }

  /// \brief Get opcode
  ///
  /// \retval opcode value
  Opcode opcode()
  {
    return static_cast<Opcode>(data_ & 0x000f);
  }

  /// \brief Set mask bit
  ///
  /// \retval reference of *this 
  AHead& mask_set()
  {
    return mask(1);
  }
  /// \brief Reset mask bit
  ///
  /// \retval reference of *this 
  AHead& mask_reset()
  {
    return mask(0);
  }

  /// \brief Get mask bit
  ///
  /// \retval Mask bit value
  int mask()
  {
    return (data_ & 0x8000) >> 15;
  }

  /// \brief Set payload len field value
  ///
  /// \param [in] val: Payload length. It is less than equal 127
  /// \retval Reference of *this 
  AHead& payload_len(int val)
  {
    assert(val <= 127);
    data_ = (data_ & 0x80ff) | (val << 8);
    return *this;
  }

  /// \brief Get payload length field value
  ///
  /// \retval Payload length field value
  int payload_len()
  {
    return (data_ & 0x7f00) >> 8;
  }

private:
  /// \brief Set/Reset FIN bit
  ///
  /// \param [in] val: FIN bit value. 1 or 0
  /// \retval Reference of *this 
  /// \note If you set !0 (e.g. 100) then set 1
  AHead& fin(int val)
  {
    int v = val == 0 ? 0 : 1;
    data_ = (data_ & 0xff7f) | (v << 7);
    return *this;
  }

  /// \brief Set/Reset RSV1 bit
  ///
  /// \param [in] val: RSV1 bit value. 1 or 0
  /// \retval Reference of *this 
  /// \note If you set !0 (e.g. 100) then set 1
  AHead& rsv1(int val)
  {
    int v = val == 0 ? 0 : 1;
    data_ = (data_ & 0xffbf) | (v << 6);
    return *this;
  }

  /// \brief Set/Reset RSV2 bit
  ///
  /// \param [in] val: RSV2 bit value. 1 or 0
  /// \retval Reference of *this 
  /// \note If you set !0 (e.g. 100) then set 1
  AHead& rsv2(int val)
  {
    int v = val == 0 ? 0 : 1;
    data_ = (data_ & 0xffdf) | (v << 5);
    return *this;
  }

  /// \brief Set RSV3 bit
  ///
  /// \param [in] val: RSV3 bit value. 1 or 0
  /// \retval Reference of *this 
  /// \note If you set !0 (e.g. 100) then set 1
  AHead& rsv3(int val)
  {
    int v = val == 0 ? 0 : 1;
    data_ = (data_ & 0xffef) | (v << 4);
    return *this;
  }

  /// \brief Set mask bit
  ///
  /// \param [in] val: Mask bit value. 1 or 0
  /// \retval reference of *this 
  /// \note If you set !0 (e.g. 100) then set 1
  AHead& mask(int val)
  {
    int v = val == 0 ? 0 : 1;
    data_ = (data_ & 0x7fff) | (v << 15);
    return *this;
  }

  uint16_t data_ = 0; // Network byte order
};

/// \brief Sockaddr class
///
/// sockaddr structure utility class
class Sockaddr final {
public:
  Sockaddr() = default;
  Sockaddr(const Sockaddr&) = default;
  Sockaddr(Sockaddr&&) = default;
  explicit Sockaddr(const struct sockaddr_storage& addr)
  {
    uaddr_.storage = addr;
  }

  /// \brief Constructer
  ///
  /// \param [in] saddr: A pointer for struct socaddr instance
  /// \param [in] addrlen: saddr object size. bytes
  /// \exception LwsockException
  Sockaddr(const struct sockaddr* saddr, socklen_t addrlen)
  {
    if (sizeof uaddr_.storage < static_cast<size_t>(addrlen)) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << "Sockaddr(saddr=" << std::hex << saddr << ", addrlen=" << std::dec << addrlen << ") addrlen is too big. [requier addrlen <= sizeof(struct sockaddr_storage)]";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    ::memcpy(&uaddr_.storage, saddr, addrlen);
  }
  ~Sockaddr() = default;

  Sockaddr& operator=(const Sockaddr&) = default;
  Sockaddr& operator=(Sockaddr&&) = default;

  /// \brief transform the adress family (AF_*) to string
  ///
  /// \pram [in] af: AF_INET, AF_INET6, AF_UNSPEC
  /// \retval string. e.g. "AF_INET"
  static std::string af2str(int af)
  {
    std::string str;
    switch (af) {
    case AF_INET:
      str = "AF_INET";
      break;
    case AF_INET6:
      str = "AF_INET6";
      break;
    case AF_UNSPEC:
      str = "AF_UNSPEC";
      break;
    default:
      str = std::to_string(af);
      break;
    }
    return str;
  }

  /// \brief Get address family. (e.g. AF_INET, AF_INET6 etc.)
  ///
  /// \retval AF_INET: IPv4
  /// \retval AF_INET6: IPv6
  /// \exception LwsockException
  int af()
  {
    if (ipaddr_.empty()) {
      ip();
    }
    return uaddr_.saddr.sa_family;
  }

  /// \brief Get ip address. result of inet_ntop(3)
  ///
  /// \retval IP address string
  /// \exception LwsockException
  std::string ip()
  {
    if (!ipaddr_.empty()) {
      return ipaddr_;
    }
    char tmp[INET6_ADDRSTRLEN] = {0};
    socklen_t len = sizeof tmp;
    switch (uaddr_.saddr.sa_family) {
    case AF_INET:
      inet_ntop(uaddr_.saddr.sa_family, &uaddr_.in.sin_addr, tmp, len);
      port_ = ntohs(uaddr_.in.sin_port);
      break;
    case AF_INET6:
      inet_ntop(uaddr_.saddr.sa_family, &uaddr_.in6.sin6_addr, tmp, len);
      port_ = ntohs(uaddr_.in6.sin6_port);
      break;
    default:
      {
        int err = as_int(LwsockErrc::INVALID_AF);
        std::ostringstream oss;
        oss << "Sockaddr::ip()" << ". sockaddr::sa_family=" << af2str(uaddr_.saddr.sa_family);
        throw LwsockException(Error(err, __LINE__, oss.str()));
      }
      break;
    }
    ipaddr_ = tmp;
    return ipaddr_;
  }

  /// \brief Get port number
  ///
  /// \exception LwsockException
  uint16_t port()
  {
    if (ipaddr_.empty()) {
      ip();
    }
    return port_;
  }
private:
  union {
    struct sockaddr_storage storage = {0};
    struct sockaddr saddr;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  } uaddr_; // union adder
  std::string ipaddr_;
  uint16_t port_ = 0;
};

/// \brief Timespec data class
class Timespec final {
public:
  enum {
    TIMEOUT_NOSPEC = -1, ///< timeout no specification. it depend on the system
  };

  Timespec() = default;

  /// \brief Constructer that the milliseconds specify
  ///
  /// \param [in] msec: Millisecond or TIMEOUT_NOSPEC
  /// \exception LwsockException
  explicit Timespec(int32_t msec)
  : msec_(msec)
  {
    if (msec == TIMEOUT_NOSPEC) {
      return;
    }

    if (msec > TIMEOUT_NOSPEC) {
      tm_ = std::make_unique<struct timespec>(timespec{msec / 1000, msec % 1000 * 1000000});
    }
    else {
      throw LwsockException(Error(as_int(LwsockErrc::INVALID_PARAM), __LINE__));
    }
  }
  ~Timespec() = default;

  bool operator==(int32_t msec) const
  {
    return msec_ == msec;
  }
  bool operator!=(int32_t msec) const
  {
    return !(*this == msec);
  }
  bool operator>(int32_t msec) const
  {
    return msec_ > msec;
  }
  bool operator<(int32_t msec) const
  {
    return !(*this > msec);
  }
  bool operator>=(int32_t msec) const
  {
    return msec_ >= msec;
  }
  bool operator<=(int32_t msec) const
  {
    return msec_ <= msec;
  }

  /// \brief Get a pointer of struct timespec instance
  ///
  /// \retval A pointer of struct timespec instance
  const struct timespec* ptr() const
  {
    return tm_.get();
  }

  /// \brief Transform to string
  ///
  /// \retval "struct timespec" string representation. (e.g. {10, 123} or NOSPEC etc.)
  std::string to_str() const
  {
    if (msec_ == TIMEOUT_NOSPEC) {
      return "NOSPEC";
    }
    else {
      return "{" + std::to_string(tm_->tv_sec) + ", " + std::to_string(tm_->tv_nsec) + "}";
    }
  }
private:
  int32_t msec_ = TIMEOUT_NOSPEC;
  std::unique_ptr<struct timespec> tm_ = nullptr;
};

/// \brief WebSocket class
///
class WebSocket final {
public:
  /// \brief Mode enum
  ///
  enum class Mode {
    NONE = -1,
    CLIENT = 0,
    SERVER,
  };

  /// \brief Opening handshake headers type
  ///
  /// vector<pair> <br>
  ///   pair::first header name <br>
  ///   pair::second value (it does not include CRLF)
  using headers_t = std::vector<std::pair<std::string, std::string>>;

  /// \brief Opening handshake type
  ///
  /// pair <br>
  ///   first: Requset line or status line (it does not include CRLF) <br>
  ///   second: headers_t
  using handshake_t = std::pair<std::string, headers_t>;

  WebSocket() = default;
  WebSocket(const WebSocket&) = delete;
  
  /// \brief Move constructor
  ///
  /// \param [in] ws: WebSocket instance
  WebSocket(WebSocket&& ws) noexcept
  {
    mode_ = ws.mode_;
    sfd_ = ws.sfd_;
    ws.sfd_ = -1;
    bind_sfds_ = std::move(ws.bind_sfds_);
    host_ = std::move(ws.host_);
    port_ = ws.port_;

    path_ = std::move(ws.path_);
    query_ = std::move(ws.query_);
    nonce_ = std::move(ws.nonce_);
    recved_rest_buff_ = std::move(ws.recved_rest_buff_);
    remote_ = std::move(ws.remote_);
  }

  /// \brief Constuctor
  ///
  /// \param [in] mode: Mode::NONE, Mode::CLIENT, Mode::SERVER
  explicit WebSocket(Mode mode)
  : mode_(mode)
  {}

  /// \brief Destructor
  ///
  ~WebSocket()
  {
    if (sfd_ != -1) {
      ::close(sfd_);
    }
    if (!bind_sfds_.empty()) {
      for (auto& sfd : bind_sfds_) {
        ::close(sfd);
      }
    }
  }

  WebSocket& operator=(const WebSocket &) = delete;
  WebSocket& operator=(WebSocket&& rhs) noexcept
  {
    mode_ = rhs.mode_;
    sfd_ = rhs.sfd_;
    rhs.sfd_ = -1;
    host_ = std::move(rhs.host_);
    port_ = rhs.port_;
    path_ = std::move(rhs.path_);
    query_ = std::move(rhs.query_);
    nonce_ = std::move(rhs.nonce_);
    recved_rest_buff_ = std::move(rhs.recved_rest_buff_);
    remote_ = std::move(rhs.remote_);

    return *this;
  }

  static std::string prefix()
  {
    return "WebSocket::";
  }

  /// \brief bind(2) with the specified address and the port number.<br>
  ///
  /// This API will bind(2) with the specified address and port number.<br>
  /// This use getaddrinfo(3) for specified the address(or host) and port number, then each call socket(2) and bind(2).
  ///
  /// \param [in] ws_addr_port: The IP address (or hostname) and the port number starting with "ws://" <br>
  ///     ws_addr_port = "ws://" address [":" port] <br>
  ///     address = hostname | IPv4_dot_decimal | IPv6_colon_hex <br>
  /// \retval reference of *this
  /// \exception CRegexException
  /// \exception GetaddrinfoException
  /// \exception LwsockExrepss
  WebSocket& bind(const std::string& ws_addr_port)
  {
    return bind(ws_addr_port, AF_UNSPEC);
  }

  /// \brief lwsock::WebSocket::bind() with the address family.<br>
  ///   If you want to explicitly specify IPv4 or IPv6 while using hostname, you should use this API.
  ///
  /// \param [in] ws_addr_port: the address and the port starting with "ws://" <br>
  ///     ws_addr_port = "ws://" address [":" port] <br>
  ///     address = hostname | IPv4_dot_decimal | IPv6_colon_hex <br>
  /// \pram [in] af: AF_INET or AF_INET6 <br>
  ///     if you want to specify that use IPv4 or IPv6 then you set this \param.
  /// \retval reference of *this
  /// \exception CRegexException
  /// \exception GetaddrinfoException
  /// \exception LwsockExrepss
  WebSocket& bind(const std::string& ws_addr_port, int af)
  {
    assert(!ws_addr_port.empty());
    assert(sfd_ == -1);

    Callee callee(prefix() + __func__, "(ws_addr_port=\"%s\", af=%d)", ws_addr_port, Sockaddr::af2str(af));

    if (mode_ != Mode::SERVER) {
      int err = as_int(LwsockErrc::INVALID_MODE);
      std::ostringstream oss;
      oss << callee.str() << " invalid mode. expect Mode::SERVER.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    if (ws_addr_port.empty()) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid ws_addr_port.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    if (af != AF_UNSPEC && af != AF_INET && af != AF_INET6) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid af=" << Sockaddr::af2str(af);
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    std::pair<std::string, std::string> hostport_pathquery;
    std::pair<std::string, std::string> host_port;
    try {
      // split into host_port part and path_query part.
      hostport_pathquery = split_hostport_pathquery(ws_addr_port);

      // split into host part and port number part.
      host_port = split_host_port(hostport_pathquery.first);
    }
    catch (LwsockException& e) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid ws_addr_port.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    //// split into path part and query part.
    //std::pair<std::string, std::string> path_query = split_path_query(hostport_pathquery.second);
    //path_ = std::move(path_query.first);
    //query_ = std::move(path_query.second);

    host_ = host_port.first;
    try {
      port_ = host_port.second.empty() ? 80 : std::stoi(host_port.second);
    }
    catch (std::invalid_argument& e) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid port number=" << host_port.second;
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    if (port_ > 65535) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid port number=" << host_port.second;
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    log_.info() << "host_=\"" << host_ << '\"' << ", port=" << port_ << std::endl;

    struct addrinfo hints = {0};
    struct addrinfo* res0 = nullptr;
    struct addrinfo* res = nullptr;
    hints.ai_flags |= AI_PASSIVE;
    hints.ai_flags |= is_numerichost(host_) ? AI_NUMERICHOST : hints.ai_flags;
    hints.ai_family
      = af == AF_INET ? AF_INET
      : af == AF_INET6 ? AF_INET6
      : AF_UNSPEC
      ;
    hints.ai_socktype = SOCK_STREAM;

    int ret = ::getaddrinfo(host_.empty() ? nullptr : host_.c_str(), std::to_string(port_).c_str(), &hints, &res0);
    if (ret != 0) {
      int err = ret;
      std::ostringstream oss;
      oss << callee.str() << " getaddrinfo(node=\"" << host_ << "\", port=" << port_ << ")";
      throw GetaddrinfoException(Error(err, __LINE__, oss.str()));
    }

    for (res = res0; res != nullptr; res = res->ai_next) {
      int sfd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sfd < 0) {
        int err = errno;
        log_.warning() << "::socket(" << res->ai_family << ", " << res->ai_socktype << ", " << res->ai_protocol << ") error=" << err << ". " << strerror(err) << ". Try next." << std::endl;
        continue;
      }
      log_.debug() << "::socket() sfd=" << sfd << std::endl;

      int on = 1;
      if (res->ai_family == AF_INET6) {
        setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
      }
      setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
      setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#if defined(SO_REUSEPORT)
      setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
#endif

      Sockaddr saddr(res->ai_addr, res->ai_addrlen);
      ret = ::bind(sfd, res->ai_addr, res->ai_addrlen);
      if (ret < 0) {
        int err = errno;
        log_.warning() << "::bind(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ") error=" << err << ". " << strerror(err) << ". closed socket. Try next." << std::endl;
        close_socket(sfd);
        continue;
      }
      log_.info() << "::bind(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ")" << std::endl;

      bind_sfds_.push_back(sfd);
    }
    freeaddrinfo(res);

    if (bind_sfds_.empty()) {
      int err = as_int(LwsockErrc::COULD_NOT_OPEN_AVAILABLE_SOCKET);
      std::ostringstream oss;
      oss << callee.str() << " could not bind(2) any sockets.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    return *this;
  }

  /// \brief listen(2) each binded sockets
  ///
  /// \param [in] backlog: listen(2)'s backlog
  /// \retval Reference of *this
  /// \exception SystemErrorException
  WebSocket& listen(int backlog)
  {
    assert(mode_ == Mode::SERVER);
    assert(!bind_sfds_.empty());

    Callee callee(prefix() + __func__, "(backlog=%d)", backlog);
    ALog::Tracer tracer(callee.str());

    std::for_each(std::begin(bind_sfds_), std::end(bind_sfds_), [&](int sfd){
      int ret = ::listen(sfd, backlog);
      if (ret != 0) {
        int err = errno;
        std::ostringstream oss;
        oss << callee.str() << "::listen(sfd=" << sfd << ", backlog=" << backlog << ")";
        throw SystemErrorException(Error(err, __LINE__, oss.str()));
      }
      log_.info() << "::listen(sfd=" << sfd << ", backlog=" << backlog << ")" << std::endl;
    });

    return *this;
  }

  /// \brief Accept socket
  ///
  /// \retval A new WebSocket instance
  /// \exception LwsockException
  /// \exception SystemErrorException
  WebSocket accept()
  {
    assert(mode_ == Mode::SERVER);
    assert(!bind_sfds_.empty());

    Callee callee(prefix() + __func__);
    ALog::Tracer tracer(callee.str());

    fd_set rfds;
    FD_ZERO(&rfds);
    int maxsfd = -1;

    log_.info() << "::pselect() wait sfds=";
    for (size_t i = 0; i < bind_sfds_.size(); ++i) {
      int sfd = bind_sfds_[i];
      FD_SET(sfd, &rfds);
      maxsfd = std::max(maxsfd, sfd);
      log_ << sfd << (i != bind_sfds_.size()-1 ? "," : "");
    }
    log_ << '\n' << std::flush;

    int nfds = maxsfd + 1;
    int ret = pselect(nfds, &rfds, nullptr, nullptr, nullptr, nullptr);
    if (ret == -1) {
      int err = errno;
      std::ostringstream oss;
      oss << callee.str() << " ::pselect(nfds=" << nfds << ", ...)";
      throw SystemErrorException(Error(err, __LINE__, oss.str()));
    }

    auto ite = std::find_if(std::begin(bind_sfds_), std::end(bind_sfds_), [&rfds](int sfd){
        if (FD_ISSET(sfd, &rfds)) {
          return true;
        }
        else {
          return false;
        }
    });
    int sfd = *ite;

    struct sockaddr_storage remote = {0};
    socklen_t addrlen = sizeof remote;
    //log_(LogLevel::INFO) << "::accept(sfd=" << sfd << ", ...)\n";
    int newsfd = ::accept(sfd, (struct sockaddr*)&remote, &addrlen);
    if (newsfd < 0) {
      int err = errno;
      std::ostringstream oss;
      oss << callee.str() << " ::accept(sfd=" << sfd << ", ...)";
      throw SystemErrorException(Error(err, __LINE__, oss.str()));
    }
    WebSocket ws(Mode::SERVER);
    ws.sfd_ = newsfd;
    ws.host_ = host_;
    ws.port_ = port_;
    remote_ = Sockaddr(remote);

    log_.info() << "::accept(sfd=" << sfd << ", ...) newsfd=" << newsfd << ", remote=" << remote_.ip() << ", port=" << remote_.port() << std::endl;
    return ws;
  }

  /// \brief Accept socket
  ///
  /// \param [out] remote: This is set in with the address of the peer socket
  /// \retval A new WebSocket instance
  /// \exception LwsockException
  /// \exception SystemErrorException
  WebSocket accept(Sockaddr& remote)
  {
    WebSocket nws = accept(); // newer WebSocket instance
    remote = nws.remote_;
    return nws;
  }

  /// \brief Receive a opening handshake request message. blocking receive
  ///
  /// \retval Received handshake message parameters
  /// \exception CRegexException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  handshake_t recv_req()
  {
    return recv_req(Timespec());
  }

  /// \brief Receive opening handshake request message with timeout. <br>
  ///   recv_req() internally calls recv(2) multiple times. timeout is effective that times.
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval Received handshake message parameters
  /// \exception CRegexException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  handshake_t recv_req(const Timespec& timeout)
  {
    assert(sfd_ != -1);
    assert(mode_ == Mode::SERVER);

    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(callee.str());

    std::string recved_response = recv_until_eoh(sfd_, timeout);
    log_.debug() << '\"' << recved_response << '\"'<< std::endl;

    handshake_t handshake_data;
    try {
      handshake_data = parse_handshake_msg(recved_response);
    }
    catch (LwsockException& e) {
      int err = as_int(LwsockErrc::INVALID_HANDSHAKE);
      std::ostringstream oss;
      oss << callee.str() << " INVALID_HANDSHAKE. send 404 and close socket=" << sfd_;
      handshake_t handshake;
      handshake.first = "HTTP/1.1 400 Bad Request";
      send_res_manually(handshake);
      close_socket(sfd_); // 10.7 when the endpoint sees an opening handshake that does not correspond to the values it is expecting, the endpoint MAY drop the TCP connection.
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    CRegex regex(R"(^GET +((/[^? ]*)(\?[^ ]*)?)? *HTTP/1\.1)", 20);
    auto tmp = regex.exec(handshake_data.first);
    if (tmp.size() < 1) {
      int err = as_int(LwsockErrc::INVALID_HANDSHAKE);
      std::ostringstream oss;
      oss << callee.str() << " INVALID_HANDSHAKE first_line=\"" << handshake_data.first << "\". send 404 and close socket=" << sfd_;
      handshake_t handshake;
      handshake.first = "HTTP/1.1 400 Bad Request";
      send_res_manually(handshake);
      close_socket(sfd_); // 10.7 when the endpoint sees an opening handshake that does not correspond to the values it is expecting, the endpoint MAY drop the TCP connection.
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    std::pair<std::string, std::string> path_query = split_path_query(tmp[1]);
    path_ = path_query.first;
    query_ = path_query.second;

    auto ite4origin = std::find_if(std::begin(handshake_data.second), std::end(handshake_data.second), [](std::pair<std::string, std::string>& headervalue){
      if (str2lower(headervalue.first) == str2lower("Origin")) {
        return true;
      }
      else {
        return false;
      }
    });
    if (ite4origin != std::end(handshake_data.second)) {
      origin_ = ite4origin->second;
    }

    try {
      check_request_headers(handshake_data.second);
    }
    catch (LwsockException& e) {
      std::ostringstream oss;
      oss << callee.str() << e.what() << " received a bad request from the client, then send 400 response and close socekt=" << sfd_;
      handshake_t handshake;
      handshake.first = "HTTP/1.1 400 Bad Request";
      send_res_manually(handshake);
      close_socket(sfd_); // 10.7 when the endpoint sees an opening handshake that does not correspond to the values it is expecting, the endpoint MAY drop the TCP connection.
      throw LwsockException(Error(e.code(), oss.str()));
    }

    return handshake_data;
  }

  /// \brief Send an opening handshake response message. <br>
  ///   Send default heades. they are Host, Upgrade, Connection, Sec-WebSocket-Key and Sec-WebSocket-Accept.
  ///
  /// \retval Sent a message 
  /// \exception SystemErrorException
  std::string send_res()
  {
    return send_res(headers_t{});
  }

  /// \brief Send opening handshake response with other headers. <br>
  ///   If you want to send that add other headers to default headers, then use this api.
  ///
  /// \param [in] otherheaders: Other headers
  /// \retval Sent a message 
  /// \exception SystemErrorException
  std::string send_res(const headers_t& otherheaders)
  {
    assert(sfd_ != -1);
    assert(mode_ == Mode::SERVER);

    Callee callee(prefix() + __func__, "() otherheaders count=%u", otherheaders.size());
    ALog::Tracer tracer(callee.str());

    handshake_t handshake;
    handshake.first = "HTTP/1.1 101 Switching Protocols\r\n";

    headers_t headers;
    headers.push_back({"Upgrade", "websocket"});
    headers.push_back({"Connection", "Upgrade"});

    std::string key = make_key(nonce_, GUID);
    headers.push_back({"Sec-WebSocket-Accept", key});
    if (!otherheaders.empty()) {
      std::copy(std::begin(otherheaders), std::end(otherheaders), std::back_inserter(headers));
    }

    handshake.second = headers;

    return send_ohandshake(handshake);
  }

  /// \brief Send an opening handshake response message that is set completely manual.
  ///
  /// \param [in] handshake: Handshake message parameters
  /// \retval Sent a message 
  /// \exception SystemErrorException
  std::string send_res_manually(const handshake_t& handshake)
  {
    return send_ohandshake(handshake);
  }

  /// \brief Connect to the server
  ///
  /// \param [in] uri: WebSocket URI <br>
  ///     uri ::= "ws://" host (":" port)? path ("?" query)? <br>
  ///     host ::= hostname | IPv4_dot_decimal | IPv6_colon_hex <br>
  /// \retval Reference of *this
  /// \exception CRegexException
  /// \exception GetaddrinfoException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  WebSocket& connect(const std::string& uri)
  {
    return connect(uri, Timespec());
  }

  /// \brief Connect to the server with timeout
  ///
  /// \param [in] uri: connect to uri. <br>
  ///     uri ::= "ws://" host (":" port)? path ("?" query)? <br>
  ///     host ::= hostname | IPv4_dot_decimal | IPv6_colon_hex <br>
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval Reference of *this
  /// \exception CRegexException
  /// \exception GetaddrinfoException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  WebSocket& connect(const std::string& uri, const Timespec& timeout)
  {
    return connect(uri, AF_UNSPEC, timeout);
  }

  /// \brief Connect to the server with timeout. and if you use hostname for uri and want to specify IPv4 or IPv6, you should use this method.
  ///
  /// \param [in] uri: connect to uri. <br>
  ///     uri ::= "ws://" host (":" port)? path? query? <br>
  ///     path is the URL path that starting "/".  e.g. "/aa/bb/cc" <br>
  ///     query is the URL query that starting "?". e.g. "?aa=12&bb=xyz" <br>
  ///     host ::= hostname | IPv4_dot_decimal | IPv6_colon_hex <br>
  /// \pram [in] af: AF_INET or AF_INET6 <br>
  ///     If you want to specify that use IPv4 or IPv6 then you set this \param.
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval Reference of *this
  /// \exception CRegexException
  /// \exception GetaddrinfoException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  WebSocket& connect(const std::string& uri, int af, const Timespec& timeout)
  {
    assert(mode_ == Mode::CLIENT);
    assert(af == AF_INET || af == AF_INET6 || af == AF_UNSPEC);
    assert(!uri.empty());
    assert(sfd_ == -1);

    Callee callee(prefix() + __func__, "(uri=\"%s\", af=%d, timeout=%s)", uri, Sockaddr::af2str(af), timeout.to_str());
    ALog::Tracer tracer(callee.str());

    // Define a function that it set nonblocking/blocking to sfd.
    // If nonblock is true, sfd is sat nonblocking.
    // If nonblock is false, sfd is sat blocking.
    auto sfd_nonblock = [](int sfd, bool nonblock) -> int {
      int val = nonblock;
      int ret = ioctl(sfd, FIONBIO, &val);
      return ret;
    };

    std::pair<std::string, std::string> hostport_pathquery;
    std::pair<std::string, std::string> host_port;
    try {
      // Split into host_port part and path_query part.
      hostport_pathquery = split_hostport_pathquery(uri);

      // Split into host part and port number part.
      host_port = split_host_port(hostport_pathquery.first);
    }
    catch (LwsockException& e) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid uri.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    // Split into path part and query part.
    std::pair<std::string, std::string> path_query = split_path_query(hostport_pathquery.second);
    path_ = path_query.first;
    query_ = std::move(path_query.second);

    host_ = host_port.first;
    try {
      port_ = host_port.second.empty() ? 80 : std::stoi(host_port.second);
    }
    catch (std::invalid_argument& e) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid port number=" << host_port.second;
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    if (port_ > 65535) {
      int err = as_int(LwsockErrc::INVALID_PARAM);
      std::ostringstream oss;
      oss << callee.str() << " invalid port number=" << host_port.second;
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    log_.info() << "host=\"" << host_ << "\", port=" << port_ << ", path=\"" << path_ << "\", query=\"" << query_  << '\"' << std::endl;

    int available_sfd = -1;
    struct addrinfo hints = {0};
    struct addrinfo* res0 = nullptr;
    struct addrinfo* res = nullptr;
    hints.ai_flags += is_numerichost(host_) ? AI_NUMERICHOST : hints.ai_flags;
    hints.ai_family
      = af == AF_INET ? AF_INET
      : af == AF_INET6 ? AF_INET6
      : AF_UNSPEC
      ;
    hints.ai_socktype = SOCK_STREAM;

    int ret = ::getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &res0);
    if (ret != 0) {
      int err = ret;
      std::ostringstream oss;
      oss << callee.str() << " getaddrinfo(node=\"" << host_ << "\", port=" << port_ << ")";
      throw GetaddrinfoException(Error(err, __LINE__, oss.str()));
    }
    for (res = res0; res != nullptr; res = res->ai_next) {
      int sfd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sfd < 0) {
        int err = errno;
        log_.warning() << "socket(" << res->ai_family << ", " << res->ai_socktype << ", " << res->ai_protocol << ") error=" << err << ". " << strerror(err) << ". Try next." << std::endl;
        continue;
      }
      log_.debug() << "socket() opened sfd=" << sfd << std::endl;

      int on = 1;
      if (res->ai_family == AF_INET6) {
        setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
      }
      setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
      sfd_nonblock(sfd, true); // Set nonblocking mode

      ret = ::connect(sfd, res->ai_addr, res->ai_addrlen);
      if (ret == 0) {
        sfd_nonblock(sfd, false); // Reset blocking mode
        Sockaddr saddr(res->ai_addr, res->ai_addrlen);
        log_.debug() << "::connect(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ") success" << std::endl;
        available_sfd = sfd;
        break;
      }
      else {
        int err = errno;
        if (err == EINPROGRESS) {
          Sockaddr saddr(res->ai_addr, res->ai_addrlen);

          fd_set rfd;
          FD_ZERO(&rfd);
          FD_SET(sfd, &rfd);
          fd_set wfd;
          FD_ZERO(&wfd);
          FD_SET(sfd, &wfd);
          ret = 0;
          log_.debug() << "::connect(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ", timeout=" << timeout.to_str() << ')' << std::endl;
          int nfds = sfd + 1;
          ret = pselect(nfds, &rfd, &wfd, nullptr, timeout.ptr(), nullptr);
          if (ret == -1) {
            int err = errno;
            std::ostringstream oss;
            oss << callee.str() << " ::pselect(nfds=" << nfds << ", ...)";
            close_socket(sfd);
            throw SystemErrorException(Error(err, __LINE__, oss.str()));
          }
          else if (ret == 0) {
            log_.warning() << "::connect() is timeouted, try next." << std::endl;
            close_socket(sfd);
            break; // try a next connection
          }
          else {
            if (FD_ISSET(sfd, &rfd)) {
              char tmp[8]; // '8' has no particular meaning.
              int err = 0;
              ret = recv(sfd, tmp, sizeof tmp, 0);
              if (ret < 0) {
                err = errno;
              }
              Sockaddr saddr(res->ai_addr, res->ai_addrlen);
              if (ret == 0) {
                log_.warning() << "::connect(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ") is closed from the server. Try next" << std::endl;
              }
              else {
                log_.warning() << "::connect(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ") error=" << err << ". " << strerror(err) << ". Try next" << std::endl;
              }
              close_socket(sfd);
              continue;
            }
            if (FD_ISSET(sfd, &wfd)) {
              // Connect successed
              sfd_nonblock(sfd, false); // Set blocking mode
              available_sfd = sfd;
              remote_ = Sockaddr(res->ai_addr, res->ai_addrlen);
              break;
            }

            throw SystemErrorException(Error(EBADE, __LINE__, "FD_ISSET() result is an unexpected."));
          }
        }
        else {
          close_socket(sfd);
          Sockaddr saddr(res->ai_addr, res->ai_addrlen);
          log_.warning() << "::connect(sfd=" << sfd << ", ip=\"" << saddr.ip() << "\", port=" << saddr.port() << ") error=" << err << ". " << strerror(err) << ". closed socket. Try next." << std::endl;

        }
      }
    }
    freeaddrinfo(res);

    if (available_sfd == -1) {
      int err = as_int(LwsockErrc::COULD_NOT_OPEN_AVAILABLE_SOCKET);
      std::ostringstream oss;
      oss << callee.str() << " COULD_NOT_OPEN_AVAILABLE_SOCKET.";
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }

    sfd_ = available_sfd;
    log_.info() << prefix() << "(sfd=" << sfd_ << ") connect success." << std::endl;

    return *this;
  }

  /// \brief Send an opening handshake request message
  ///
  /// \retval Sent a message 
  std::string send_req()
  {
    return send_req(headers_t{});
  }

  /// \brief Send an opening handshake request message with other headers
  ///
  /// \param [in] otherheaders: Other headers
  /// \retval Sent a message 
  /// \exception SystemErrorException
  std::string send_req(const headers_t& otherheaders)
  {
    assert(sfd_ != -1);
    assert(mode_ == Mode::CLIENT);

    Callee callee(prefix() + __func__, "() otherheaders cnt=%u", otherheaders.size());
    ALog::Tracer tracer(callee.str());

    std::ostringstream first_line;
    first_line << "GET " << path_ << query_ << " HTTP/1.1" << EOL;

    handshake_t handshake;
    handshake.first = first_line.str();

    headers_t headers;
    headers.push_back({"Host", (port_ == 80) ? host_ : (host_ + ":" + std::to_string(port_))});
    headers.push_back({"Upgrade", "websocket"});
    headers.push_back({"Connection", "Upgrade"});
    nonce_ = make_nonce();
    headers.push_back({"Sec-WebSocket-Key", nonce_});
    headers.push_back({"Sec-WebSocket-Version", "13"});
    if (!otherheaders.empty()) {
      std::copy(std::begin(otherheaders), std::end(otherheaders), std::back_inserter(headers));
    }

    handshake.second = headers;

    return send_ohandshake(handshake);
  }

  /// \brief Send an opening handshake request message that is set completely manual.
  ///
  /// \param [in] handshake: Handshake message parameters
  /// \retval Sent a message 
  /// \exception SystemErrorException
  std::string send_req_manually(const handshake_t& handshake)
  {
    return send_ohandshake(handshake);
  }

  /// \brief Receive an opening handshake response message
  ///
  /// \retval pair::first: Received handshake message parameters <br>
  ///         pair::second: Status code of the 1st line <br>
  /// \exception CRegexException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<handshake_t, int32_t> recv_res()
  {
    return recv_res(Timespec());
  }

  /// \brief Receive an opening handshake response message with timeout
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval pair::first: Received handshake params <br>
  ///         pair::second: Status code <br>
  /// \exception CRegexException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<handshake_t, int32_t> recv_res(const Timespec& timeout)
  {
    assert(sfd_ != -1);

    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(callee.str());

    std::string recved_response = recv_until_eoh(sfd_, timeout);

    handshake_t handshake_data = parse_handshake_msg(recved_response);
    CRegex regex(R"(^HTTP/1.1 ([0-9]+)(.*)?)", 20);
    std::vector<std::string> tmp = regex.exec(handshake_data.first);

    if (tmp.size() < 3) {
      int err = as_int(LwsockErrc::INVALID_HANDSHAKE);
      std::ostringstream oss;
      oss << callee.str() << " INVALID_HANDSHAKE first_line=\"" << handshake_data.first << "\", then send CLOSE frame and close socket=" << sfd_;
      send_close(1002);
      close_socket(sfd_); // 10.7 when the endpoint sees an opening handshake that does not correspond to the values it is expecting, the endpoint MAY drop the TCP connection.
      throw LwsockException(Error(err, __LINE__, oss.str()));
    }
    int32_t status_code = std::stoi(tmp[1]);
    if (status_code != 101) {
      return std::pair<handshake_t, int32_t> {{}, status_code};
    }

    try {
      check_response_headers(handshake_data.second);
    }
    catch (LwsockException& e) {
      std::ostringstream oss;
      oss << callee.str() << e.what() << ", then send CLOSE frame and close socket=" << sfd_;
      send_close(1002);
      close_socket(sfd_); // 10.7 when the endpoint sees an opening handshake that does not correspond to the values it is expecting, the endpoint MAY drop the TCP connection.
      throw LwsockException(Error(e.code(), __LINE__, oss.str()));
    }

    log_.debug() << handshake_data.first << std::endl;
    for (auto& elm : handshake_data.second) {
      log_.debug() << elm.first << ':' << elm.second << '\n';
    }
    log_.debug() << std::endl;

    return std::pair<handshake_t, int32_t>(handshake_data, status_code);
  }

  /// \brief Send a websocket text message to the remote
  ///
  /// \param [in] payload_data: WebSocket payload data
  /// \retval Sent data size. bytes
  /// \exception SystemErrorException
  ssize_t send_msg_txt(const std::string& payload_data)
  {
    return send_msg(Opcode::TEXT, payload_data.data(), payload_data.size());
  }

  /// \brief Send a websocket binary message to the remote
  ///
  /// \param [in] payload_data: WebSocket payload data
  /// \retval Sent data size. bytes
  /// \exception SystemErrorException
  ssize_t send_msg_bin(const std::vector<uint8_t>& payload_data)
  {
    return send_msg(Opcode::BINARY, payload_data.data(), payload_data.size());
  }

  /// \brief Send a websocket binary message to the remote
  ///
  /// \param [in] payload_data: WebSocket payload data
  /// \retval Sent data size. bytes
  /// \exception SystemErrorException
  template<size_t N> ssize_t send_msg_bin(const std::array<uint8_t, N>& payload_data)
  {
    return send_msg(Opcode::BINARY, payload_data.data(), payload_data.size());
  }

  /// \brief Receive a websocket text message from the remote
  ///
  /// \retval pair::first: A received string message <br>
  ///         pair::second: Status code when recieved a CLOSE frame <br>
  /// \exception CRegexException
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<std::string, int32_t> recv_msg_txt()
  {
    return recv_msg_txt(Timespec());
  }

  /// \brief Receive a websocket text message from the remote with timeout
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval pair::first: A received string message <br>
  ///         pair::second: Status code when recieved a CLOSE frame <br>
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<std::string, int32_t> recv_msg_txt(const Timespec& timeout)
  {
    assert(sfd_ != -1);

    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(callee.str());

    std::pair<std::string, int32_t> result = recv_msg<std::string>(timeout);

    return result;
  }

  /// \brief Receive a websocket binary message from the remote
  ///
  /// \retval pair::first: A received binary message <br>
  ///         pair::second: Status code when recieved a CLOSE frame <br>
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<std::vector<uint8_t>, int32_t> recv_msg_bin()
  {
    return recv_msg_bin(Timespec());
  }

  /// \brief Receive a websocket binary message from the remote with timeout
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval pair::first: A received binary message <br>
  ///         pair::second: Status code when recieved a CLOSE <br>
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::pair<std::vector<uint8_t>, int32_t> recv_msg_bin(const Timespec& timeout)
  {
    assert(sfd_ != -1);

    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(callee.str());

    std::pair<std::vector<uint8_t>, int32_t> result = recv_msg<std::vector<uint8_t>>(timeout);
    return result;
  }

  /// \brief Send a PING frame
  ///
  /// \retval Sent data size. bytes
  /// \exception SystemErrorException
  ssize_t send_ping()
  {
    return send_msg(Opcode::PING, "", 0);
  }

  /// \brief Send a PING frame with a text app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent data size. bytes
  /// \exception SystemErrorException
  ssize_t send_ping(const std::string& app_data)
  {
    return send_msg(Opcode::PING, app_data.data(), app_data.size());
  }

  /// \brief Send PING frame with a binary app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent size. bytes
  /// \exception SystemErrorException
  ssize_t send_ping(const std::vector<uint8_t>& app_data)
  {
    return send_msg(Opcode::PING, app_data.data(), app_data.size());
  }

  /// \brief Send PING frame with a binary app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent size. bytes
  /// \exception SystemErrorException
  template<size_t N> ssize_t send_ping(const std::array<uint8_t, N>& app_data)
  {
    return send_msg(Opcode::PING, app_data.data(), app_data.size());
  }

  /// \brief Send a PONG frame
  ///
  /// \retval Sent size. bytes
  /// \exception SystemErrorException
  ssize_t send_pong()
  {
    return send_msg(Opcode::PONG, nullptr, 0);
  }

  /// \brief Send a PONG frame with a text app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent size. bytes
  /// \exception SystemErrorException
  ssize_t send_pong(const std::string& app_data)
  {
    Callee callee(prefix() + __func__, "(app_data text=\"%s\")", app_data);
    ALog::Tracer tracer(callee.str());

    return send_msg(Opcode::PONG, app_data.data(), app_data.size());
  }

  /// \brief Send a PONG frame with a binary app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent size. bytes
  /// \exception SystemErrorException
  ssize_t send_pong(const std::vector<uint8_t>& app_data)
  {
    Callee callee(prefix() + __func__, "(app_data binary=...) (not yet implement)");
    ALog::Tracer tracer(callee.str());

    return send_msg(Opcode::PONG, app_data.data(), app_data.size());
  }

  /// \brief Send a PONG frame with a binary app data
  ///
  /// \param [in] app_data: App data
  /// \retval Sent size. Bytes
  /// \exception SystemErrorException
  template<size_t N> ssize_t send_pong(const std::array<uint8_t, N>& app_data)
  {
    Callee callee(prefix() + __func__, "(app_data binary=...) (not yet implement)");
    ALog::Tracer tracer(callee.str());

    return send_msg(Opcode::PONG, app_data.data(), app_data.size());
  }

  /// \brief Send CLOSE frame. send CLOSE frame, then wait a response (maybe CLOSE frame) or wait closing socket from the remote.
  ///
  /// \param [in] status_code: Status code
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  void send_close(const uint16_t status_code)
  {
    send_close(status_code, "", Timespec());
  }

  /// \brief Send CLOSE frame. send CLOSE frame, then wait a response (maybe CLOSE frame) or wait closing socket from the remote.
  ///
  /// \param [in] status_code: Status code
  /// \param [in] reason: Reason string
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  void send_close(const uint16_t status_code, const std::string& reason)
  {
    send_close(status_code, reason, Timespec());
  }

  /// \brief Send CLOSE frame with timeout. send CLOSE frame, then wait a response (maybe CLOSE frame) or wait closing socket from the remote.
  ///
  /// \param [in] status_code: Status code
  /// \param [in] reason: Reason
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  void send_close(const uint16_t status_code, const std::string& reason, const Timespec& timeout)
  {
    Callee callee(prefix() + __func__, "(status_code=%h, reason=\"%s\", timeout=%s)", status_code, reason, timeout.to_str());
    ALog::Tracer tracer(callee.str());

    std::vector<uint8_t> appdata(sizeof status_code + reason.size());
    {
      uint16_t be_scode = htons(status_code); // big endian status code
      uint8_t* p = &appdata[0];
      ::memcpy(p, &be_scode, sizeof be_scode);
      p += sizeof be_scode;
      ::memcpy(p, reason.data(), reason.size());
    }
    try {
      send_msg(Opcode::CLOSE, appdata.data(), appdata.size());
    }
    catch (SystemErrorException& see) {
      if (see.code() == EBADF || see.code() == EPIPE) {
        ; // NOP
      }
      else {
        throw see;
      }
    }
    close_websocket(sfd_, timeout);
  }

  /// \brief Get Sockaddr about the remote
  ///
  /// \retval Sockaddr
  Sockaddr remote()
  {
    return remote_;
  }

  /// \brief Get the request path
  ///
  /// \retval Path (e.g. "/path/a/b/c")
  std::string path()
  {
    return path_;
  }

  /// \brief Set the request path
  ///
  /// \retval Path (e.g. "/path/a/b/c")
  void path(const std::string& req_path)
  {
    path_ = req_path;
  }
  void path(std::string&& req_path)
  {
    path_ = std::move(req_path);
  }

  /// \brief Get the request query parameters.
  ///
  /// \retval Query (e.g. "?aa=123&bb=xyz")
  std::string query()
  {
    return query_;
  }

  /// \brief Set the request query parameters.
  ///
  /// \retval Query (e.g. "?aa=123&bb=xyz")
  void query(const std::string& req_query)
  {
    query_ = req_query;
  }
  void query(std::string&& req_query)
  {
    query_ = std::move(req_query);
  }

  /// \brief Get the Origin header's value in the request headers, if client is a web browser.
  ///
  /// \retval A value of Origin header
  std::string origin()
  {
    return origin_;
  }

  /// \brief Get the raw sockfd that connected or accepted. You must not close it.
  ///
  /// \retval Raw sockfd
  /// \note: You must not close the socket
  int raw_sfd()
  {
    return sfd_;
  }

  /// \brief [[deprecated]] Get the raw sockfd that connected or accepted. you must not close it.
  ///
  /// \retval Raw sockfd
  /// \note: You must not close the socket
  [[deprecated("please use raw_sfd()")]]
  int sfd_ref()
  {
    return sfd_;
  }

  /// \brief Get the raw sockfd that connected or accepted.
  ///
  /// \retval Raw sockfd
  /// \note: You must close the socket yourself when sockfd was no necessary
  [[deprecated("obsoleted")]]
  int sfd_mv()
  {
    int sfd = sfd_;
    init();
    return sfd;
  }

  /// \brief Get reference of binded sockfds
  ///
  /// \retval Socket fds
  /// \note: You must not close the socket
  const std::vector<int>& bind_sfds()
  {
    return bind_sfds_;
  }

  /// \brief Set ostream for log. output log to the ostream
  ///
  /// \param [in] ost: ostream
  /// \retval Reference of *this
  WebSocket& ostream4log(std::ostream& ost)
  {
    log_.ostream(ost);
    return *this;
  }

  /// \briaf Set log level
  ///
  /// \param [in] lvl: Log level
  /// \retval Reference of *this
  WebSocket& loglevel(LogLevel lvl)
  {
    log_.level(lvl);
    return *this;
  }

  /// \brief Get now log level

  /// \retval Now log level
  LogLevel loglevel()
  {
    return log_.level();
  }

private:
  /// \brief Transform the string to the lowercase string
  ///
  /// \param [in] str: Target string
  /// \retval Lower case string
  static std::string str2lower(const std::string& str)
  {
    std::string result;
    std::transform(std::begin(str), std::end(str), std::back_inserter(result), ::tolower);
    return result;
  }

  /// \brief Transform the string to the uppercase string
  ///
  /// \param [in] str: Target string
  /// \retval Upper case string
  static std::string str2upper(const std::string& str)
  {
    std::string result;
    std::transform(std::begin(str), std::end(str), std::back_inserter(result), ::toupper);
    return result;
  }

  void init()
  {
    //mode_ = Mode::NONE;
    sfd_ = -1;
    host_.clear();
    port_ = 0;
    path_.clear();
    query_.clear();
    nonce_.clear();
    recved_rest_buff_ = std::vector<uint8_t>();
    remote_ = Sockaddr();
  }

  /// \brief Close sockfd
  ///
  /// \param [in out] sfd: Socket fd
  void close_socket(int& sfd)
  {
    Callee callee(prefix() + __func__, "(sfd=%d)", sfd);
    if (sfd != -1) {
      ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

      log_.info() << "::close(sfd=" << sfd << ')' << std::endl;

      int ret = ::close(sfd);
      if (ret == -1) {
        int err = errno;
        std::ostringstream oss;
        oss << "::close(sfd=" << sfd << ')' << std::endl;
        Error(err, oss.str());
      }

      sfd = -1;

      if (!recved_rest_buff_.empty()) {
        recved_rest_buff_.clear();
      }
    }
  }

  /// \brief Close websocket with timeout. refered RFC6455 7.1.1.
  ///
  /// \param [in out] sfd: Socket fd
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \exception SystemErrorException
  void close_websocket(int& sfd, const Timespec& timeout)
  {
    Callee callee(prefix() + __func__, "(sfd=%d, timeout=%s)", sfd, timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    if (sfd == -1) {
      return;
    }

    if (::shutdown(sfd, SHUT_WR) == 0) {
      uint8_t buff[16] = {0};
      try {
        recv_with_timeout(sfd, buff, sizeof buff, timeout);
      }
      catch (SystemErrorException& see) {
        if (see.code() == EBADF || see.code() == ECONNREFUSED) {
          ; // NOP
        }
        else {
          throw see;
        }
      }
    }
    close_socket(sfd);
  }

  /// \brief Send opening handshake
  ///
  /// \param [in] handshake_data: Handshake data
  /// \retval String transformed handshake data 
  /// \exception SystemErrorException
  std::string send_ohandshake(const handshake_t& handshake_data)
  {
    Callee callee(prefix() + __func__, "(handshake_data=...) not yet implement");
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    std::string first_line = handshake_data.first;
    headers_t headers = handshake_data.second;

    std::ostringstream oss;
    oss << first_line;
    for (auto& header : headers) {
      oss << header.first << ": " << header.second << EOL;
    }
    oss << EOL;
    //log_(LogLevel::DEBUG) << "\"" << oss.str() << "\" size=" << std::dec << oss.str().size() << std::endl;
    log_.debug() << '\"' << oss.str() << '\"' << std::endl;

    size_t ret = send_fill(sfd_, oss.str().c_str(), oss.str().size());
    assert(ret == oss.str().size());
    log_.debug() << "sent size=" << oss.str().size() << std::endl;
    return oss.str();
  }

  /// \brief Receive a message with timeout
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval pair::first: Received a message. if websocket was closed from the remote, then size()==0 <br>
  ///         pair::second: Staus code when websocket is closed from the remote <br>
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  template<typename T> std::pair<T, int32_t> recv_msg(const Timespec& timeout)
  {
    static_assert(std::is_base_of<T, std::string>::value || std::is_base_of<T, std::vector<uint8_t>>::value, "Require T is std::string or std::vector<uint8_t>");

    assert(sfd_ != -1);
    assert(timeout >= -1);

    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    std::pair<T, int32_t> result{{}, 0};
    AHead ahead;
    bool txtflg = false;
    do {
      log_.debug() << "  [[ receive a part of header ..." << std::endl;
      ssize_t ret = recv_fill(sfd_, ahead.data_ptr(), ahead.size(), timeout);
      if (ret == 0) { // Socket is closed.
        result.first.clear();
        result.second = 1006; // RFC6455 7.1.5. "The WebSocket Connection Close Code is considered to be 1006."
        close_socket(sfd_);
        return result;
      }
      log_.debug() << "  ]] receive a part of header...result="
        << " raw=0x" << std::hex << std::setw(4) << std::setfill('0') << ahead.data() << std::dec
        << ", fin=" << ahead.fin() << ", rsv1=" << ahead.rsv1() << ", rsv2=" << ahead.rsv2() << ", rsv3=" << ahead.rsv3()
        << ", opcode=0x" << std::hex << std::setw(2) << std::setfill('0') << as_int(ahead.opcode()) << std::setw(0) << std::dec
        << ", mask=" << ahead.mask()
        << ", payload_len=" << ahead.payload_len() << std::endl
        ;

      if (ahead.opcode() == Opcode::TEXT) {
        txtflg = true;
      }
      if (ahead.rsv1() != 0 || ahead.rsv2() != 0 || ahead.rsv3() != 0) {
        int err = as_int(LwsockErrc::FRAME_ERROR);
        std::ostringstream oss;
        oss << callee.str() << " rsv1=" << ahead.rsv1() << ", rsv2=" << ahead.rsv2() << ", rsv3=" << ahead.rsv3();
        log_.warning() << oss.str() << std::endl;
        close_websocket(sfd_, timeout);
        throw LwsockException(Error(err, __LINE__, oss.str()));
      }

      uint64_t payload_len = 0;
      switch (ahead.payload_len()) {
      case 126:
        {
          uint16_t tmp = 0;
          ret = recv_fill(sfd_, &tmp, sizeof tmp, timeout);
          // TODO ret <= 0 case
          payload_len = ntohs(tmp);
        }
        break;
      case 127:
        {
          uint64_t tmp = 0;
          // for environment without be64ton() or betoh64()
          auto be2h64 = [](uint64_t be) -> uint64_t {
            uint64_t ret = 0;
            uint32_t* p32_1 = reinterpret_cast<uint32_t*>(&be);
            uint32_t* p32_2 = p32_1 + 1;
            uint32_t le_1 = ntohl(*p32_1);
            uint32_t le_2 = ntohl(*p32_2);
            uint32_t* r1 = reinterpret_cast<uint32_t*>(&ret);
            uint32_t* r2 = r1 + 1;
            ::memcpy(r1, &le_2, sizeof le_2);
            ::memcpy(r2, &le_1, sizeof le_1);
            return ret;
          };
          ret = recv_fill(sfd_, &tmp, sizeof tmp, timeout);
          // TODO ret <= 0 case
          payload_len = be2h64(tmp);
        }
        break;
      default:
        payload_len = ahead.payload_len();
        break;
      }
      log_.debug() << "  eventually payload len=" << payload_len << std::endl;

      if ((mode_ == Mode::SERVER && ahead.mask() == 0) || (mode_ == Mode::CLIENT && ahead.mask() == 1)) {
        int err = as_int(LwsockErrc::BAD_MESSAGE);
        std::ostringstream oss;
        oss << callee.str() << "received invalid maskbit=" << ahead.mask() << ", then send CLOSE 1002 frame, then close socket=" << sfd_;
        send_close(1002);
        close_socket(sfd_);
        throw LwsockException(Error(err, __LINE__, oss.str()));
      }

      uint32_t masking_key = 0;
      if (ahead.mask()) {
        log_.debug() << "  [[ receive masking key..." << std::endl;
        ret = recv_fill(sfd_, &masking_key, sizeof masking_key, timeout);
        // TODO ret == 0 case
        log_.debug() << "  ]] receive masking key...raw=0x" << std::hex << std::setw(8) << std::setfill('0') << masking_key << std::endl;
      }

      // receive payload data
      std::vector<uint8_t> tmp_recved(payload_len);
      ret = recv_fill(sfd_, &tmp_recved[0], tmp_recved.size(), timeout);
      // TODO ret == 0 case

      std::vector<uint8_t> payload_data;
      if (ahead.mask()) {
        payload_data = mask_data(tmp_recved.data(), tmp_recved.size(), masking_key);
      }
      else {
        payload_data = std::move(tmp_recved);
      }

      switch (ahead.opcode()) {
      case Opcode::CONTINUE:
      case Opcode::TEXT: 
      case Opcode::BINARY: 
        break;

      case Opcode::PING:
        {
          log_.info() << "received Ping frame. app_data_sz=" << payload_data.size() << ", then send PONG" << std::endl;
          send_pong(payload_data);
        }
        continue;
      case Opcode::PONG:
        log_.info() << "received Pong frame. app_data_sz=" << payload_data.size() << std::endl;
        continue;
      case Opcode::CLOSE:
        {
          uint16_t scode = 0; // Status code;
          std::string reason;
          if (payload_data.size() > 0) {
            uint16_t be_scode = 0; // Big endian status code
            ::memcpy(&be_scode, payload_data.data(), sizeof be_scode);
            scode = ntohs(be_scode); // Status code
            log_.info() << "received CLOSE frame from the remote, status_code=" << std::dec << scode << ", then send CLOSE" << std::endl;
            result.first.clear();
            result.second = scode;
          }
          else {
            log_.info() << "received CLOSE frame from the remote, status_code is none," << ", then send CLOSE" << std::endl;
            result.first.clear();
            result.second = 1005;
            reason = "RFC6455 7.1.5. \"If this Close control frame contains no status code, The WebSocket Connection Close Code is considered to be 1005.\"";
          }
          try {
            if (scode != 0) {
              send_close(scode, reason, timeout);
            }
            else {
              send_close(timeout);
            }
          }
          catch (SystemErrorException& e) {
            if (e.code() == EBADF || e.code() == EPIPE) {
                ; // NOP. Socket is closed already
            }
            else {
              throw e;
            }
          }
          close_socket(sfd_);
        }
        continue;

      default: // Faild
        // TODO
        close_socket(sfd_);
        continue;
      }
      // Append received data
      std::copy(std::begin(payload_data), std::end(payload_data), std::back_inserter(result.first));
    } while (ahead.fin() == 0 && ahead.opcode() != Opcode::CLOSE);

    if (txtflg) {
      // TODO
      // Check if result is UTF-8 data.
    }

    return result;
  }

  /// \brief Send a message
  ///
  /// \pwaram [in] opcode: opcode
  /// \param [in] payload_data_org : Extension data + app data
  /// \param [in] payload_data_sz: Payload_data_org object size. Bytes
  /// \retval Sent size
  /// \exception SystemErrorException
  ssize_t send_msg(Opcode opcode, const void* payload_data_org, const size_t payload_data_sz)
  {
    assert(mode_ == Mode::CLIENT || mode_ == Mode::SERVER);
    assert(sfd_ != -1);
    assert(opcode == Opcode::TEXT || opcode == Opcode::BINARY || opcode == Opcode::CLOSE || opcode == Opcode::PING);

    Callee callee(prefix() + __func__, "(opcode=0x%02x, payload_data=..., payload_data_sz=%u", as_int(opcode), payload_data_sz);
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    AHead ahead;
    ahead.fin_set();
    ahead.opcode(opcode);
    if (mode_ == Mode::CLIENT) {
      ahead.mask_set();
    }
    else {
      ahead.mask_reset();
    }

    union {
      uint16_t bit16;
      uint64_t bit64;
    } ext_payload_len = {0};
    if (payload_data_sz <= 125) {
      ahead.payload_len(payload_data_sz);
    }
    else if (payload_data_sz <= 0xffff) {
      ahead.payload_len(126);
      ext_payload_len.bit16 = htons(payload_data_sz);
    }
    else {
      ahead.payload_len(127);
      ext_payload_len.bit64 = htobe64(payload_data_sz);
    }
    uint64_t frame_sz
      = ahead.size()
      + (ahead.payload_len() <= 125 ? 0 : ahead.payload_len() == 126 ? sizeof ext_payload_len.bit16 : sizeof ext_payload_len.bit64) // Extended payload length
      + (mode_ == Mode::CLIENT ? 4 : 0) // for masking key
      + payload_data_sz
      ;

    std::vector<uint8_t> frame(frame_sz);
    uint8_t* p = &frame[0];

    ::memcpy(p, ahead.data_ptr(), ahead.size());
    p += ahead.size();

    if (ahead.payload_len() == 126) {
      ::memcpy(p, &ext_payload_len.bit16, sizeof ext_payload_len.bit16);
      p += sizeof ext_payload_len.bit16;
    }
    else if (ahead.payload_len() == 127) {
      ::memcpy(p, &ext_payload_len.bit64, sizeof ext_payload_len.bit64);
      p += sizeof ext_payload_len.bit64;
    }

    if (mode_ == Mode::CLIENT) {
      std::mt19937 rd;
      std::uniform_int_distribution<uint32_t> dist(0, 0xffffffff);
      uint32_t masking_key = dist(rd);

      ::memcpy(p, &masking_key, sizeof masking_key);
      p += sizeof masking_key;

      std::vector<uint8_t> payload_data = mask_data(payload_data_org, payload_data_sz, masking_key);
      ::memcpy(p, payload_data.data(), payload_data_sz);
    }
    else {
      ::memcpy(p, payload_data_org, payload_data_sz);
    }

    ssize_t sentsz = send_fill(sfd_, frame.data(), frame.size());

    tracer.clear() << "WebSocket::send_msg(opcode=0x" << std::hex << std::setw(2) << std::setfill('0') << as_int(opcode) << std::dec << ", ...) total sent size=" << sentsz;

    return sentsz;
  }

  /// \brief Send data untill specified size
  ///
  /// \param [in] sfd: Socket fd
  /// \param [in] buff: Data pointer
  /// \param [in] buffsz: Buff object size
  /// \retval Sent size
  /// \exception SystemErrorException
  ssize_t send_fill(int sfd, const void* buff, const size_t buffsz)
  {
    Callee callee(prefix() + __func__, "(sfd=%d, buff=..., buffsz=%u)", sfd, buffsz);
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    const uint8_t* ptr = static_cast<const uint8_t*>(buff);
    size_t sent_sz = 0;

    while (sent_sz < buffsz) {
      int ret = ::send(sfd, ptr, buffsz - sent_sz, MSG_NOSIGNAL);
      if (ret < 0) {
        int err = errno;
        std::ostringstream oss;
        oss << callee.str() << " ::send(sfd=" << sfd << ", ...)";
        throw SystemErrorException(Error(err, __LINE__, oss.str()));
      }

      ptr += ret;
      sent_sz += ret;

      // Urge context switching.
      struct timespec ts{0, 1};
      nanosleep(&ts, nullptr);
    }

    tracer.clear() << prefix() << "(sfd=" << sfd << ", ...) result=" << sent_sz;
    return sent_sz;
  }

  /// \brief recv(2) with timeout.
  ///
  /// \param [in] sfd: Socket fd
  /// \param [out] buff: Buffer pointer
  /// \param [in] buffsz: Buffer size
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \reval > 0 Received size
  /// \reval ==0 Socket was closed
  /// \exception SystemErrorException
  ssize_t recv_with_timeout(int sfd, void* buff, size_t buffsz, const Timespec& timeout)
  {
    Callee callee(prefix() + __func__, "(sfd=%d, buff=..., buffsz=%u, timeout=%s)", sfd, buffsz, timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    fd_set rfd;
    FD_ZERO(&rfd);
    FD_SET(sfd, &rfd);
    int nfds = sfd + 1;
    int ret = pselect(nfds, &rfd, nullptr, nullptr, timeout.ptr(), nullptr);
    if (ret == 0) {
      int err = as_int(LwsockErrc::TIMED_OUT);
      std::ostringstream oss;
      oss << callee.str() << " ::peslect(nfds=" << nfds << ", ...) TIMED OUT.";
      throw SystemErrorException(Error(err, __LINE__, oss.str()));
    }
    else if (ret == -1) {
      int err = errno;
      std::ostringstream oss;
      oss << callee.str() << " ::pselect(nfds=" << nfds << ", ...) errno=" << err;
      throw SystemErrorException(Error(err, __LINE__, oss.str()));
    }

    ssize_t result = recv(sfd, buff, buffsz, 0);
    if (result == -1) {
      int err = errno;
      std::ostringstream oss;
      oss << callee.str() << " ::recv(sfd=" << sfd << ", ...) error.";
      throw SystemErrorException(Error(err, __LINE__, oss.str()));
    }

    tracer.clear() << prefix() << "(sfd=" << sfd << ", ...) result=" << result;
    return result;
  }

  /// \brief Receive untill specified size with timeout
  ///
  /// \param [in] sfd: Socket fd
  /// \param [out] buff: Buffer's pointer
  /// \param [in] expect_sz: Expect size
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \reval > 0 Received size
  /// \reval ==0 Socket was closed
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  ssize_t recv_fill(int sfd, void* buff, const size_t expect_sz, const Timespec& timeout)
  {
    assert(sfd != -1);

    Callee callee(prefix() + __func__, "(sfd=%d, buff=..., expect_sz=%u, timeout=%s", sfd, expect_sz, timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    uint8_t* ptr = static_cast<uint8_t*>(buff);
    size_t recved_sz = 0;

    // if Received data when opening handshake is rest, then copy it
    log_.debug() << "    recved_rest_buff.size()=" << recved_rest_buff_.size() << std::endl;
    if (!recved_rest_buff_.empty()) {
      size_t sz = recved_rest_buff_.size();
      if (sz > expect_sz) {
        memcpy(ptr, &recved_rest_buff_[0], expect_sz);
        std::vector<uint8_t> rest(std::begin(recved_rest_buff_)+expect_sz, std::end(recved_rest_buff_));
        recved_rest_buff_ = std::move(rest);
        return expect_sz;
      }
      memcpy(ptr, &recved_rest_buff_[0], sz);
      recved_rest_buff_.clear();
      ptr += sz;
      recved_sz += sz;
    }

    ssize_t ret = 0;
    while (recved_sz < expect_sz && (ret = recv_with_timeout(sfd, ptr, expect_sz - recved_sz, timeout)) > 0) {
      ptr += ret;
      recved_sz += ret;

      // Urge context switching.
      struct timespec ts{0, 1};
      nanosleep(&ts, nullptr);
    }

    ret = recved_sz == expect_sz ? recved_sz : ret;

    tracer.clear() << "WebSocket::recv_fill(sfd=" << sfd << ", ...) result=" << ret;
    return ret;
  }

  /// \brief Receive untill CRLFCRLF. if there is data after CRLFCRLF, save it
  ///
  /// \param [in] sfd: Socket fd
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// \retval Received data
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  std::string recv_until_eoh(int sfd, const Timespec& timeout)
  {
    assert(recved_rest_buff_.empty());

    Callee callee(prefix() + __func__, "(sfd=%d, timeout=%s)", sfd, timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    std::string recved_msg;

    constexpr char EOH[] = "\r\n\r\n"; // End of header
    constexpr std::string::size_type NPOS = std::string::npos;
    std::string::size_type pos = NPOS;
    while ((pos = recved_msg.find(EOH)) == NPOS) {
      char tmp[512] = {0};
      ssize_t ret = recv_with_timeout(sfd, tmp, (sizeof tmp) -1, timeout); // -1 is that tmp[] has at least '\0'.
      if (ret == 0) {
        int err = as_int(LwsockErrc::SOCKET_CLOSED);
        std::ostringstream oss;
        oss << callee.str() << " socket was closed from the remote.";
        throw LwsockException(Error(err, __LINE__, oss.str()));
      }
      recved_msg += tmp;

      // Urge context switching.
      struct timespec ts{0, 1};
      nanosleep(&ts, nullptr);
    }

    constexpr int eohsz = sizeof EOH -1; // End of header size
    std::string result = recved_msg.substr(0, pos + eohsz); // result data include CRLFCRLF

    // If there is data after crlfcrl, save that data to recved_rest_buff_
    if (pos + eohsz < recved_msg.size()) {
      std::copy(std::begin(recved_msg) + pos + eohsz, std::end(recved_msg), std::back_inserter(recved_rest_buff_));
    }

    log_.debug() << result << std::endl;

    return result;
  }

  /// \brief Send empty body CLOSE frame.
  ///
  /// \param [in] timeout: Specify timeout. Timespec instance
  /// This function is when receiving empty body CLOSE frame, then called.
  /// \exception LwsockExrepss
  /// \exception SystemErrorException
  void send_close(const Timespec& timeout)
  {
    Callee callee(prefix() + __func__, "(timeout=%s)", timeout.to_str());
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());
    send_msg(Opcode::CLOSE, nullptr, 0);
    close_websocket(sfd_, timeout);
  }

  /// \brief Split headers
  ///
  /// \param [in] lines_msg: Headers string
  /// \retval Splited headers
  std::vector<std::pair<std::string, std::string>> split_headers(const std::string& lines_msg)
  {
    Callee callee(prefix() + __func__, "(lines_msg=%s)", lines_msg);
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    using size_type = std::string::size_type;
    constexpr size_type NPOS(std::string::npos);

    std::vector<std::pair<std::string, std::string>> headers;
    for (size_type p0 = 0, pos = NPOS; (pos = lines_msg.find(EOL, p0)) != NPOS; p0 = pos + 2) {
      std::string line = lines_msg.substr(p0, pos - p0);
      if (line.empty()) {
        break;
      }
      size_type p = line.find_first_of(':');
      std::string header_name = line.substr(0, p);
      std::string value = p == NPOS ? "" : trim(line.substr(p+1));
      log_.debug() << "  header_name=\"" << header_name << "\", value=\"" << value << '\"' << std::endl;
      headers.push_back(std::make_pair(std::move(header_name), std::move(value)));
    }

    return headers;
  }

  /// \brief Check response headers
  ///
  /// \param [in] hlines: Splited headers
  /// \exception LwsockException
  void check_response_headers(const std::vector<std::pair<std::string, std::string>>& hv_lines)
  {
    Callee callee(prefix() + __func__, "(\n");
    for (auto& element : hv_lines) {
      callee << "    " << element.first << ": " << element.second << '\n';
    }
    callee << ")";
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    // Check "Upgrade" header
    {
      std::string header_name = "Upgrade";
      auto ite = std::find_if(std::begin(hv_lines), std::end(hv_lines), [&header_name](auto& hv){
        if (str2lower(hv.first) == str2lower(header_name))
        { return true; }
        else
        { return false; }
      });
      if (ite == std::end(hv_lines)) {
        std::ostringstream oss;
        oss << " \"" << header_name << "\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
      if (str2lower(ite->second) != "websocket") {
        std::ostringstream oss;
        oss << " \"" << header_name << ": " << ite->second << "\" dose not include \"websocket\".";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
    }

    // check "Connection" header
    {
      std::string header_name = "Connection";
      auto ite = std::find_if(std::begin(hv_lines), std::end(hv_lines), [&header_name](auto& hv){
        if (str2lower(hv.first) == str2lower(header_name))
        { return true; }
        else
        { return false; }
      });
      if (ite == std::end(hv_lines)) {
        std::ostringstream oss;
        oss << " \"" << header_name << "\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
      std::string str = str2lower(ite->second);
      std::string token = str2lower("Upgrade");
      if (str.find(token) == std::string::npos) {
        std::ostringstream oss;
        oss << " \"" << header_name << ": " << ite->second << "\" dose not include \"Upgrade\".";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
    }

    // check "Sec-WebSocket-Accept"
    {
      std::string header_name = "Sec-WebSocket-Accept";
      auto ite = std::find_if(std::begin(hv_lines), std::end(hv_lines), [&header_name](auto& hv){
        if (str2lower(hv.first) == str2lower(header_name))
        { return true; }
        else
        { return false; }
      });
      if (ite == std::end(hv_lines)) {
        std::ostringstream oss;
        oss << " \"" << header_name << "\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
      std::string key = make_key(nonce_, GUID);
      if (ite->second != key) {
        std::ostringstream oss;
        oss << " invalid \"Sec-WebSocket-Accept: " << ite->second << '\"';
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), __LINE__, oss.str()));
      }
    }

    tracer.clear() << "WebSocket::check_response_headers() ok";
  }

  /// \brief Check request headers
  ///
  /// \param [in] hlines: Splited headers
  /// \exception LwsockException
  void check_request_headers(const std::vector<std::pair<std::string, std::string>>& hv_lines)
  {
    Callee callee(prefix() + __func__, "(\n");
    for (auto& element : hv_lines) {
      callee << "    \"" << element.first << "\": \"" << element.second << "\"\n";
    }
    callee << ")";
    ALog::Tracer tracer(LogLevel::DEBUG, callee.str());

    // Check "Host" header existing
    { auto ite = std::find_if(std::begin(hv_lines), std::end(hv_lines), [](auto& hv){
        if (str2lower(hv.first) == str2lower("Host")) {
          return true;
        }
        else {
          return false;
        }
      });
      if (ite == std::end(hv_lines)) {
        std::ostringstream oss;
        oss << " \"Host\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
    }

    // Extract values of "Upgrade" header. It header is possible multiple.
    {
      std::vector<std::string> values; // "Upgrade" Header's values
      std::for_each(std::begin(hv_lines), std::end(hv_lines), [&values](auto& hvs){
        if (str2lower(hvs.first) == str2lower("Upgrade")) {
          values.push_back(hvs.second);
        }
      });
      if (values.empty()) {
        std::ostringstream oss;
        oss << " \"Upgrade\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
      auto ite = std::find_if(std::begin(values), std::end(values), [](const std::string& value){
        auto str = str2lower(value);
        if (str.find("websocket") != std::string::npos) {
          return true;
        }
        else {
          return false;
        }
      });
      if (ite == std::end(values)) {
        std::ostringstream oss;
        oss << " \"Upgrade\" header does not have the value of \"websocket\".";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
    }

    // Extract values of "Connection" header. It header is possible multiple.
    {
      std::vector<std::string> values; // "Connection" Header's values
      std::for_each(std::begin(hv_lines), std::end(hv_lines), [&values](auto& hv){
        if (str2lower(hv.first) == str2lower("Connection")) {
          values.push_back(hv.second);
        }
      });
      if (values.empty()) {
        std::ostringstream oss;
        oss << " \"Connection\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
      auto ite = std::find_if(std::begin(values), std::end(values), [](const std::string& value){
        std::string str = str2lower(value);
        std::string token = str2lower("Upgrade");
        if (str.find(token) != std::string::npos) {
          return true;
        }
        else {
          return false;
        }
      });
      if (ite == std::end(values)) {
        std::ostringstream oss;
        oss << " \"Connection\" header does not include the value of \"Upgrade\".";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
    }

    // Search "Sec-WebSocket-Key"
    {
      auto sec_websocket_key_line = std::find_if(std::begin(hv_lines), std::end(hv_lines), [](auto& hv){
        if (str2lower(hv.first) == str2lower("Sec-WebSocket-Key")) {
          return true;
        }
        else {
          return false;
        }
      });
      if (sec_websocket_key_line == std::end(hv_lines)) {
        std::ostringstream oss;
        oss << " \"Sec-WebSocket-Key\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
      std::vector<uint8_t> value = Base64::decode(sec_websocket_key_line->second);
      if (value.size() != 16) {
        std::ostringstream oss;
        oss << " \"Sec-WebSocket-Key\" header is invalid size: " << std::to_string(value.size());
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
      nonce_ = sec_websocket_key_line->second;
    }

    // Extract values of "Sec-WebSocket-Version" header. It header is possible multiple.
    {
      std::vector<std::string> values; // "Sec-WebSocket-Version" Header's values
      std::for_each(std::begin(hv_lines), std::end(hv_lines), [&values](auto& hvs){
        if (str2lower(hvs.first) == str2lower("Sec-WebSocket-Version")) {
          values.push_back(hvs.second);
        }
      });
      if (values.empty()) {
        std::ostringstream oss;
        oss << " \"Sec-WebSocket-Version\" header is not found.";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
      auto ite = std::find_if(std::begin(values), std::end(values), [](const std::string& value){
        std::string str = str2lower(value);
        std::string token = "13";
        if (str.find(token) != std::string::npos) {
          return true;
        }
        else {
          return false;
        }
      });
      if (ite == std::end(values)) {
        std::ostringstream oss;
        oss << " \"Sec-WebSocket-Version\" header does not include \"13\".";
        throw LwsockException(Error(as_int(LwsockErrc::INVALID_HANDSHAKE), oss.str()));
      }
    }
  }

  /// \biref Make a nonce for a opening handshake
  ///
  /// \param nonce
  std::string make_nonce()
  {
    constexpr static int NONCE_SZ = 16;
    std::mt19937 rd;
    std::uniform_int_distribution<uint64_t> dist(0, 0xffffffffffffffff);
    uint64_t tmp = dist(rd);
    std::array<uint8_t, NONCE_SZ> x1;
    assert(sizeof tmp < x1.size());
    ::memcpy(&x1[0], &tmp, sizeof tmp);
    ::memcpy(&x1[8], &Magic[0], x1.size()-8);
    std::string nonce = Base64::encode(x1);
    return nonce;
  }

  /// \brief Make a key for a opening handshake
  ///
  /// \param key
  std::string make_key(const std::string& nonce, const std::string& guid)
  {
    std::string key = nonce + guid;
    Sha1::Context_t ctx;
    Sha1::Input(ctx, key.data(), key.size());
#if 1
    uint8_t sha1val[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(sha1val, sizeof sha1val, ctx);
    std::string b64 = Base64::encode(sha1val, sizeof sha1val);
#else
    std::array<uint8_t, Sha1::SHA1_HASH_SIZE> sha1val;
    ~~~
    ~~~
#endif
    return b64;
  }

  /// \brief Parse a opening handshake message
  ///
  /// \param [in] Received handshake message
  /// \retval Parsed handshake message
  /// \exception LwsockException
  handshake_t parse_handshake_msg(const std::string& handshake_msg)
  {
    using size_type = std::string::size_type;
    size_type pos = handshake_msg.find(EOL);
    if (pos == std::string::npos) {
      int err = as_int(LwsockErrc::INVALID_HANDSHAKE);
      std::ostringstream oss;
      oss << "invliad handshake=\"" << handshake_msg << '\"';
      throw LwsockException(Error(err, oss.str()));
    }
    std::string first_line = handshake_msg.substr(0, pos);
    size_type headers_start_pos = pos + (sizeof EOL -1); // -1 is for '\0'
    headers_t headers = split_headers(handshake_msg.substr(headers_start_pos));

    return handshake_t{first_line, headers};
  }

  /// \brief Mask data
  ///
  /// \param [in] src: Data pointer
  /// \param [in] src_sz: Data size. Bytes
  /// \param [in] masking_key: Masking key
  /// \retval Masked data
  std::vector<uint8_t> mask_data(const void* src, size_t src_sz, uint32_t masking_key)
  {
    std::vector<uint8_t> masked_data(src_sz);
    const uint8_t* p0 = static_cast<const uint8_t*>(src);
    const uint8_t* p1 = reinterpret_cast<const uint8_t*>(&masking_key);
    for (size_t i = 0; i < src_sz; ++i) {
      uint8_t j = i % 4;
      uint8_t ti = p0[i] ^ p1[j];
      masked_data[i] = ti;
    }
    return masked_data;
  }

  constexpr static char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  constexpr static char EOL[] = "\r\n"; // End Of Line

  ALog& log_ = ALog::get_instance();
  Mode mode_ = Mode::NONE;
  int sfd_ = -1;
  std::vector<int> bind_sfds_;
  std::string host_;
  uint32_t port_ = 0;
  std::string path_;
  std::string query_;
  std::string nonce_;
  std::string origin_;
  std::vector<uint8_t> recved_rest_buff_;
  Sockaddr remote_;
};

} // namespace lwsock
