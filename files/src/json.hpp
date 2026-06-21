// ---------------------------------------------------------------------------
//  json.hpp  -  a small, dependency-free JSON reader
//
//  I rolled my own parser here on purpose. The whole tool is meant to drop into
//  an analyst box and just build with the Windows SDK, so I didn't want to drag
//  in a third-party header. This is a straight recursive-descent parser - the
//  same shape you'd write on a whiteboard - with a lazy value type on top so the
//  call sites read nicely:  doc["data"]["attributes"]["last_analysis_stats"].
//
//  It is read-only. We never serialise anything back out, so there is no writer.
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <cmath>
#include <sstream>

namespace argus {
namespace json {

class Value;
using Array  = std::vector<Value>;
using Object = std::map<std::string, Value>;

enum class Type { Null, Bool, Number, String, Array, Object };

// A JSON node. Numbers are kept as double - good enough for the analysis-stats
// counters and reputation scores we read back from the APIs.
class Value {
public:
    Value() : type_(Type::Null), bool_(false), num_(0.0) {}

    // --- type checks -------------------------------------------------------
    Type   type()      const { return type_; }
    bool   is_null()   const { return type_ == Type::Null; }
    bool   is_bool()   const { return type_ == Type::Bool; }
    bool   is_number() const { return type_ == Type::Number; }
    bool   is_string() const { return type_ == Type::String; }
    bool   is_array()  const { return type_ == Type::Array; }
    bool   is_object() const { return type_ == Type::Object; }

    // --- scalar getters, each with a fallback so callers never throw -------
    bool        as_bool  (bool d = false)               const { return is_bool()   ? bool_ : d; }
    double      as_double(double d = 0.0)               const { return is_number() ? num_  : d; }
    long long   as_int   (long long d = 0)              const { return is_number() ? (long long)llround(num_) : d; }
    std::string as_string(const std::string& d = "")    const { return is_string() ? str_  : d; }

    size_t size() const {
        if (is_array())  return arr_.size();
        if (is_object()) return obj_.size();
        return 0;
    }

    bool contains(const std::string& key) const {
        return is_object() && obj_.find(key) != obj_.end();
    }

    // Object lookup. A missing key returns a shared "null" node rather than
    // throwing, so chained access like a["b"]["c"] stays safe even when the
    // server omitted a field.
    const Value& operator[](const std::string& key) const {
        static const Value null_node;
        if (!is_object()) return null_node;
        auto it = obj_.find(key);
        return it == obj_.end() ? null_node : it->second;
    }

    // Array indexing, same null-safe idea.
    const Value& operator[](size_t i) const {
        static const Value null_node;
        if (!is_array() || i >= arr_.size()) return null_node;
        return arr_[i];
    }

    const Array&  items()   const { static const Array  e; return is_array()  ? arr_ : e; }
    const Object& members() const { static const Object e; return is_object() ? obj_ : e; }

private:
    Type        type_;
    bool        bool_;
    double      num_;
    std::string str_;
    Array       arr_;
    Object      obj_;

    friend class Parser;
};

// ---------------------------------------------------------------------------
//  The parser itself. Single pass over the buffer, one cursor, classic.
// ---------------------------------------------------------------------------
class Parser {
public:
    explicit Parser(const std::string& text) : s_(text), i_(0) {}

    Value parse() {
        skip_ws();
        Value v = parse_value();
        skip_ws();
        // Trailing junk is suspicious - surface it rather than silently ignore.
        if (i_ != s_.size())
            throw std::runtime_error("trailing characters after JSON document");
        return v;
    }

private:
    const std::string& s_;
    size_t             i_;

    [[noreturn]] void fail(const std::string& why) {
        std::ostringstream os;
        os << "JSON parse error at byte " << i_ << ": " << why;
        throw std::runtime_error(os.str());
    }

    char peek() {
        if (i_ >= s_.size()) fail("unexpected end of input");
        return s_[i_];
    }
    char get() {
        if (i_ >= s_.size()) fail("unexpected end of input");
        return s_[i_++];
    }
    bool more() const { return i_ < s_.size(); }

    void skip_ws() {
        while (i_ < s_.size()) {
            char c = s_[i_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i_;
            else break;
        }
    }

    Value parse_value() {
        skip_ws();
        char c = peek();
        switch (c) {
            case '{': return parse_object();
            case '[': return parse_array();
            case '"': { Value v; v.type_ = Type::String; v.str_ = parse_string(); return v; }
            case 't': case 'f': return parse_bool();
            case 'n': return parse_null();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
                fail(std::string("unexpected character '") + c + "'");
        }
    }

    Value parse_object() {
        Value v; v.type_ = Type::Object;
        get(); // consume '{'
        skip_ws();
        if (peek() == '}') { get(); return v; }
        for (;;) {
            skip_ws();
            if (peek() != '"') fail("expected string key in object");
            std::string key = parse_string();
            skip_ws();
            if (get() != ':') fail("expected ':' after object key");
            v.obj_.emplace(std::move(key), parse_value());
            skip_ws();
            char c = get();
            if (c == ',') continue;
            if (c == '}') break;
            fail("expected ',' or '}' in object");
        }
        return v;
    }

    Value parse_array() {
        Value v; v.type_ = Type::Array;
        get(); // consume '['
        skip_ws();
        if (peek() == ']') { get(); return v; }
        for (;;) {
            v.arr_.push_back(parse_value());
            skip_ws();
            char c = get();
            if (c == ',') continue;
            if (c == ']') break;
            fail("expected ',' or ']' in array");
        }
        return v;
    }

    Value parse_bool() {
        Value v; v.type_ = Type::Bool;
        if (s_.compare(i_, 4, "true") == 0)  { i_ += 4; v.bool_ = true;  return v; }
        if (s_.compare(i_, 5, "false") == 0) { i_ += 5; v.bool_ = false; return v; }
        fail("invalid literal, expected true/false");
    }

    Value parse_null() {
        if (s_.compare(i_, 4, "null") == 0) { i_ += 4; return Value(); }
        fail("invalid literal, expected null");
    }

    Value parse_number() {
        size_t start = i_;
        if (peek() == '-') get();
        while (more() && std::isdigit((unsigned char)peek())) get();
        if (more() && peek() == '.') { get(); while (more() && std::isdigit((unsigned char)peek())) get(); }
        if (more() && (peek() == 'e' || peek() == 'E')) {
            get();
            if (more() && (peek() == '+' || peek() == '-')) get();
            while (more() && std::isdigit((unsigned char)peek())) get();
        }
        Value v; v.type_ = Type::Number;
        v.num_ = std::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
        return v;
    }

    // Reads a JSON string starting at the opening quote, handling the standard
    // escape set plus \uXXXX (encoded out as UTF-8 so the rest of the program
    // can treat everything as a plain std::string).
    std::string parse_string() {
        std::string out;
        if (get() != '"') fail("expected opening quote");
        for (;;) {
            char c = get();
            if (c == '"') break;
            if (c == '\\') {
                char e = get();
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u':  append_utf8(out, read_hex4()); break;
                    default:   fail("invalid escape sequence");
                }
            } else {
                out += c;
            }
        }
        return out;
    }

    unsigned read_hex4() {
        unsigned cp = 0;
        for (int k = 0; k < 4; ++k) {
            char c = get();
            cp <<= 4;
            if      (c >= '0' && c <= '9') cp |= (c - '0');
            else if (c >= 'a' && c <= 'f') cp |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') cp |= (c - 'A' + 10);
            else fail("invalid hex digit in \\u escape");
        }
        return cp;
    }

    // Handle the surrogate-pair dance for code points above the BMP, then emit
    // UTF-8 bytes.
    void append_utf8(std::string& out, unsigned cp) {
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            // high surrogate - expect a \uXXXX low surrogate to follow
            if (get() != '\\' || get() != 'u') fail("expected low surrogate");
            unsigned lo = read_hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail("invalid low surrogate");
            cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
        }
        if (cp <= 0x7F) {
            out += (char)cp;
        } else if (cp <= 0x7FF) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
};

// Convenience free function used everywhere else in the codebase.
inline Value parse(const std::string& text) {
    return Parser(text).parse();
}

} // namespace json
} // namespace argus
