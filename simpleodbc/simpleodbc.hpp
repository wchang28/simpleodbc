#pragma once

#ifdef _WIN32
    #include <windows.h>
#endif
#include <sql.h>
#include <sqlext.h>
#include <string>
#include <exception>
#include <vector>
#include <map>
#include <memory>
#include <sstream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <stdlib.h>
#include <ww898/utf_converters.hpp>

#define SIMPLEODBC_MULTILINE_FAILURE_BEGIN do {

/* Disable warning C4127 (conditional expression is constant) when
   wrapping macros with the do { ... } while(false) construct on MSVC
*/
#if defined(_MSC_VER)
#define SIMPLEODBC_MULTILINE_FAILURE_END \
        __pragma(warning(push)) \
        __pragma(warning(disable:4127)) \
        } while(false) \
        __pragma(warning(pop))
#else
#define SIMPLEODBC_MULTILINE_FAILURE_END } while(false)
#endif


#define SIMPLEODBC_MULTILINE_ASSERTION_BEGIN do {

/* Disable warning C4127 (conditional expression is constant) when
   wrapping macros with the do { ... } while(false) construct on MSVC
*/
#if defined(_MSC_VER)
#define SIMPLEODBC_MULTILINE_ASSERTION_END \
        __pragma(warning(push)) \
        __pragma(warning(disable:4127)) \
        } while(false) \
        __pragma(warning(pop))
#else
#define SIMPLEODBC_MULTILINE_ASSERTION_END } while(false)
#endif


/*! \def SIMPLEODBC_FAIL
    \brief throw an error (possibly with file and line information)
*/
#define SIMPLEODBC_FAIL(message) \
SIMPLEODBC_MULTILINE_FAILURE_BEGIN \
    std::ostringstream _SIMPLEODBC_msg_stream; \
    _SIMPLEODBC_msg_stream << message; \
    throw simpleodbc::Error(__FILE__,__LINE__,_SIMPLEODBC_msg_stream.str()); \
SIMPLEODBC_MULTILINE_FAILURE_END


/*! \def SIMPLEODBC_ASSERT
    \brief throw an error if the given condition is not verified
*/
#define SIMPLEODBC_ASSERT(condition,message) \
SIMPLEODBC_MULTILINE_ASSERTION_BEGIN \
if (!(condition)) { \
    std::ostringstream _SIMPLEODBC_msg_stream; \
    _SIMPLEODBC_msg_stream << message; \
    throw simpleodbc::Error(__FILE__,__LINE__,_SIMPLEODBC_msg_stream.str()); \
} \
SIMPLEODBC_MULTILINE_ASSERTION_END

/*! \def SIMPLEODBC_REQUIRE
    \brief throw an error if the given pre-condition is not verified
*/
#define SIMPLEODBC_REQUIRE(condition,message) \
SIMPLEODBC_MULTILINE_ASSERTION_BEGIN \
if (!(condition)) { \
    std::ostringstream _SIMPLEODBC_msg_stream; \
    _SIMPLEODBC_msg_stream << message; \
    throw simpleodbc::Error(__FILE__,__LINE__,_SIMPLEODBC_msg_stream.str()); \
} \
SIMPLEODBC_MULTILINE_ASSERTION_END

/*! \def SIMPLEODBC_ENSURE
    \brief throw an error if the given post-condition is not verified
*/
#define SIMPLEODBC_ENSURE(condition,message) \
SIMPLEODBC_MULTILINE_ASSERTION_BEGIN \
if (!(condition)) { \
    std::ostringstream _SIMPLEODBC_msg_stream; \
    _SIMPLEODBC_msg_stream << message; \
    throw simpleodbc::Error(__FILE__,__LINE__,_SIMPLEODBC_msg_stream.str()); \
} \
SIMPLEODBC_MULTILINE_ASSERTION_END

namespace simpleodbc {
    class base64_encoding {
        base64_encoding() = delete;
    public:
        static const std::string& get_base64_chars() {
            static std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";
            return base64_chars;
        }
        static std::string encode(
            const std::vector<unsigned char>& input
        ) {
            const auto& base64_chars = get_base64_chars();
            std::string encoded;
            int val = 0, valb = -6;
            for (unsigned char c : input) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (encoded.size() % 4) encoded.push_back('=');
            return encoded;
        }
        static std::vector<unsigned char> decode(const std::string& input) {
            const auto& base64_chars = get_base64_chars();
            std::vector<int> T(256, -1);
            for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

            std::vector<unsigned char> decoded;
            int val = 0, valb = -8;
            for (unsigned char c : input) {
                if (T[c] == -1) break;
                val = (val << 6) + T[c];
                valb += 6;
                if (valb >= 0) {
                    decoded.push_back((val >> valb) & 0xFF);
                    valb -= 8;
                }
            }
            return decoded;
        }
    };

    class Error : public std::exception {
    private:
        static std::string format(
            const std::string& file,
            long line,
            const std::string& message
        ) {
            std::ostringstream msg;
            msg << "\n  " << file << "(" << line << "): \n";
            msg << message;
            return msg.str();
        }
        std::shared_ptr<std::string> message_;
    public:
        /*! The explicit use of this constructor is not advised.
            Use the SIMPLEODBC_FAIL macro instead.
        */
        Error(
            const std::string& file,
            long line,
            const std::string& message = ""
        ) {
            message_ = std::make_shared<std::string>(
                format(file, line, message)
            );
        }
        //! returns the error message.
        const char* what() const noexcept override {
            return message_->c_str();
        }
    };

    class sql_error : public std::exception {
    private:
        nlohmann::json j_;
        std::string s_;
    public:
        sql_error()
            : j_(nlohmann::json::array()), s_("[]")
        {}
        void appendErrorRecord(
            SQLSMALLINT recordNumber,
            const SQLCHAR* state, 
            const SQLCHAR* message,
            SQLINTEGER nativeError
        ) {
            nlohmann::json j_record = nlohmann::json::object();
            j_record["rec_no"] = recordNumber;
            if (state != nullptr) {
                j_record["state"] = std::string((const char*)state);
            }
            else {
                j_record["state"] = nullptr;
            }
            if (message != nullptr) {
                j_record["message"] = std::string((const char*)message);
            }
            else {
                j_record["message"] = nullptr;
            }
            j_record["native_err"] = nativeError;
            j_.push_back(j_record);
            s_ = j_.dump();
        }
        const char* what() const noexcept {
            return s_.c_str();
        }
    };

    struct column_info {
        SQLSMALLINT colNumber;
        std::string name;
        SQLSMALLINT dataType;
        SQLULEN colSize;
        SQLSMALLINT decimalDigits;
        bool nullable;
        column_info(
            SQLSMALLINT colNumber = 0,
            std::string name = "",
            SQLSMALLINT dataType = SQL_UNKNOWN_TYPE,
            SQLULEN colSize = 0,
            SQLSMALLINT decimalDigits = 0,
            bool nullable = true
        ) :
            colNumber(colNumber),
            name(name),
            dataType(dataType),
            colSize(colSize),
            decimalDigits(decimalDigits),
            nullable(nullable)
        {}
        // can be parseInt() by javascript
        bool is_integer_type() const {
            return (
                dataType == SQL_INTEGER ||
                dataType == SQL_TINYINT ||
                dataType == SQL_SMALLINT ||
                dataType == SQL_BIGINT
            );
        }
        // can be parseFloat() by javascript
        bool is_float_type() const {
            return (
                dataType == SQL_DECIMAL ||
                dataType == SQL_NUMERIC ||
                dataType == SQL_REAL ||
                dataType == SQL_FLOAT ||
                dataType == SQL_DOUBLE
            );
        }
        bool is_numeric() const {
            return (is_integer_type() || is_float_type());
        }
        // true or false
        bool is_boolean_type() const {
            return (dataType == SQL_BIT);
        }
        bool is_char_type() const {
            return (
                dataType == SQL_VARCHAR ||
                dataType == SQL_CHAR ||
                dataType == SQL_LONGVARCHAR
            );
        }
        bool is_wchar_type() const {
            return (
                dataType == SQL_WVARCHAR ||
                dataType == SQL_WCHAR ||
                dataType == SQL_WLONGVARCHAR
            );
        }
        bool is_string_type() const {
            return (is_char_type() || is_wchar_type() || dataType == SQL_GUID);
        }
        bool is_datetime_type() const {
            return (
                dataType == SQL_TYPE_TIMESTAMP ||
                dataType == SQL_TYPE_DATE ||
                dataType == SQL_TYPE_TIME
            );
        }
        bool is_buffer_type() const {
            return (
                dataType == SQL_VARBINARY ||
                dataType == SQL_BINARY
            );
        }
        bool is_unknown_type() const {
            return (!is_numeric() && !is_boolean_type() && !is_string_type() && !is_datetime_type() && !is_buffer_type());
        }
        // field need to be stringify-ed (i.e. double quoted) in a json
        bool need_to_be_stringified() const {
            return (is_string_type() || is_datetime_type() || is_unknown_type());
        }
    };

    template <
        typename Elmt
    >
    struct basic_string_or_null {
        typedef std::basic_string<Elmt, std::char_traits<Elmt>, std::allocator<Elmt>> string_type;
        bool is_null;
        string_type val;
        basic_string_or_null(
            bool is_null = false,
            const string_type& val = string_type()
        ) :is_null(is_null), val(val)
        {}
        operator string_type() const {
            SIMPLEODBC_REQUIRE(!is_null, "value is null not string");
            return val;
        }
    };
    using string_or_null = basic_string_or_null<char>;

    struct byte_array_or_null {
        bool is_null;
        std::vector<SQLCHAR> val;
        byte_array_or_null(
            bool is_null = false,
            const std::vector<SQLCHAR> val = std::vector<SQLCHAR>()
        ) :is_null(is_null), val(val)
        {}
        byte_array_or_null(
            std::vector<SQLCHAR>&& val
        ) :is_null(false), val(val)
        {}
        operator const std::vector<SQLCHAR>& () const {
            SIMPLEODBC_REQUIRE(!is_null, "value is null not bytes_array");
            return val;
        }
    };

    template <
        typename SQL_Elmt
    >
    struct basic_string_value_traits {
        typedef SQL_Elmt sql_char_type;
        typedef basic_string_or_null<SQL_Elmt> string_or_null_type;
        static SQLSMALLINT target_type() {
            throw std::logic_error("not implmented");
        }
    };
    template <>
    struct basic_string_value_traits<SQLCHAR> {
        typedef SQLCHAR sql_char_type;
        typedef basic_string_or_null<SQLCHAR> string_or_null_type;
        static SQLSMALLINT target_type() {
            return SQL_C_CHAR;
        }
    };
    template <>
    struct basic_string_value_traits<SQLWCHAR> {
        typedef SQLWCHAR sql_char_type;
        typedef basic_string_or_null<SQLWCHAR> string_or_null_type;
        static SQLSMALLINT target_type() {
            return SQL_C_WCHAR;
        }
    };

    class odbc_object {
    protected:
        odbc_object() {}
        static void checkHandleError(
            SQLRETURN ret,
            SQLHANDLE handle,
            SQLSMALLINT type
        ) {
            if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO) {
                return;
            }
            SQLSMALLINT i = 0;
            SQLINTEGER native = 0;
            SQLCHAR state[7];
            SQLCHAR text[500];
            SQLSMALLINT len = 0;
            SQLRETURN diagRet = SQL_ERROR;
            sql_error error;
            do {
                diagRet = SQLGetDiagRec(type, handle, ++i, state, &native, text, sizeof(text), &len);
                if (SQL_SUCCEEDED(diagRet)) {
                    error.appendErrorRecord(i, state, text, native);
                }
            } while (diagRet == SQL_SUCCESS);
            throw error;
        }
    };

    // base class for odbc resources such as odbc connection and statement
    class odbc_resurce : public odbc_object {
    protected:
        odbc_resurce() {}
    public:
        // for odbc resources, copy constructor and copy equal operator are not allowed
        // they can only have moving constructor or moving equal operator
        odbc_resurce(const odbc_resurce&) = delete;
        odbc_resurce& operator= (const odbc_resurce&) = delete;
    };

    // forward class declarations
    class statement;
    class connection;

    class cursor : public odbc_object {
    private:
        SQLHSTMT hStmt_;
        mutable std::vector<column_info> column_infos_;
        mutable std::map<std::string, size_t> lookup_;
        mutable std::map<std::string, string_or_null> fetched_row_;
    private:
        void checkError(
            SQLRETURN ret
        ) const {
            checkHandleError(ret, hStmt_, SQL_HANDLE_STMT);
        }
        void requireValid() const {
            SIMPLEODBC_REQUIRE(valid(), "not a valid cursor object");
        }
        void getColumnInfos() const {
            column_infos_.clear();
            lookup_.clear();
            SQLSMALLINT numCols = 0;
            auto ret = SQLNumResultCols(hStmt_, &numCols);
            checkError(ret);
            std::vector<column_info> columns;
            for (SQLSMALLINT i = 1; i <= numCols; ++i) {
                try {
                    SQLCHAR colName[500];
                    SQLSMALLINT colNameLen = 0;
                    column_info ci(i);
                    SQLSMALLINT nullable = SQL_NULLABLE;
                    ret = SQLDescribeCol(hStmt_, i, colName, sizeof(colName), &colNameLen, &(ci.dataType), &(ci.colSize), &(ci.decimalDigits), &nullable);
                    checkError(ret);
                    SIMPLEODBC_ASSERT(colNameLen < sizeof(colName) / sizeof(colName[0]), "column name length (" << colNameLen << ") is unexpected too long");
                    ci.name = (const char*)colName;
                    ci.nullable = (nullable == SQL_NULLABLE);
                    lookup_[ci.name] = column_infos_.size();
                    column_infos_.push_back(ci);
                }
                catch (const std::exception& e) {
                    SIMPLEODBC_FAIL("error retrieving column " << i << " info: " << e.what());
                }
            }
        }
        size_t columnIndex(
            const std::string& colName
        ) const {
            auto p = lookup_.find(colName);
            SIMPLEODBC_REQUIRE(p != lookup_.end(), colName << " is not valid column name");
            const auto& index = p->second;
            SIMPLEODBC_ASSERT(index >= 0 && index < column_infos_.size(), "invalid column index (" << index << "). the valid range is [0, " << column_infos_.size() << ")");
            return index;
        }

        template<
            typename SVT = basic_string_value_traits<SQLCHAR>
        >
        typename SVT::string_or_null_type column_value_as_string_impl(
            SQLSMALLINT columnNumber
        ) const {
            using SQLCharElmt = typename SVT::sql_char_type;
            auto TargetType = SVT::target_type();
            using string_or_null_type = typename SVT::string_or_null_type;
            using string_type = std::basic_string<SQLCharElmt, std::char_traits<SQLCharElmt>, std::allocator<SQLCharElmt>>;
            SQLCharElmt buffer[256];
            SQLLEN indicator = 0;
            // Fetch the data in chunks
            auto ret = SQLGetData(hStmt_, columnNumber, TargetType, buffer, sizeof(buffer), &indicator);
            checkError(ret);
            SIMPLEODBC_ASSERT(ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO, "ret (" << ret << ") must be either SQL_SUCCESS or SQL_SUCCESS_WITH_INFO");
            if (indicator == SQL_NULL_DATA) {
                return string_or_null_type(true);
            }
            else if (indicator < 0) {
                SIMPLEODBC_FAIL("SQLGetData() returns with bad indicator (" << indicator << ")");
            }
            else {  // indicator >= 0
                string_type s((const SQLCharElmt*)buffer);
                auto lengthRetrieved = s.length();
                auto totalDataLength = (size_t)indicator/sizeof(SQLCharElmt);
                if (totalDataLength > lengthRetrieved) {
                    SIMPLEODBC_ASSERT(ret == SQL_SUCCESS_WITH_INFO, "ret (" << ret << ") must be SQL_SUCCESS_WITH_INFO");
                    auto lengthRemained = totalDataLength - lengthRetrieved;
                    auto p_buf = calloc(lengthRemained + 1, sizeof(SQLCharElmt));
                    SQLLEN buf_size = (lengthRemained + 1) * sizeof(SQLCharElmt);
                    ret = SQLGetData(hStmt_, columnNumber, TargetType, (SQLPOINTER)p_buf, buf_size, &indicator);
                    SIMPLEODBC_ASSERT(ret == SQL_SUCCESS, "SQLGetData() must returns SQL_SUCCESS, instead it returns " << ret);
                    SIMPLEODBC_ASSERT((size_t)indicator/sizeof(SQLCharElmt) == lengthRemained, "indicator (" << indicator << ") is not what's expected (" << lengthRemained << ")");
                    string_type addl((const SQLCharElmt*)p_buf);
                    free(p_buf);
                    p_buf = nullptr;
                    s += addl;
                }
                return string_or_null_type(false, s);
            }
        }
        byte_array_or_null get_binary_data_column_value(SQLSMALLINT columnNumber) const {
            SQLCHAR varbinaryData[256];
            SQLLEN indicator = 0;
            auto ret = SQLGetData(hStmt_, columnNumber, SQL_C_BINARY, varbinaryData, sizeof(varbinaryData), &indicator);
            checkError(ret);
            SIMPLEODBC_ASSERT(ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO, "ret (" << ret << ") must be either SQL_SUCCESS or SQL_SUCCESS_WITH_INFO");
            if (indicator == SQL_NULL_DATA) {
                return byte_array_or_null(true);
            }
            else if (indicator < 0) {
                SIMPLEODBC_FAIL("SQLGetData() returns with bad indicator (" << indicator << ")");
            }
            else {  // indicator >= 0
                auto totalDataLength = (size_t)indicator / sizeof(SQLCHAR);
                auto buffLen = sizeof(varbinaryData) / sizeof(varbinaryData[0]);
                std::vector<SQLCHAR> v(totalDataLength, 0);
                if (totalDataLength > buffLen) {
                    memcpy(v.data(), varbinaryData, sizeof(varbinaryData));
                    auto lengthRemained = totalDataLength - buffLen;
                    auto p_buf = calloc(lengthRemained, sizeof(SQLCHAR));
                    SQLLEN buf_size = lengthRemained * sizeof(SQLCHAR);
                    ret = SQLGetData(hStmt_, columnNumber, SQL_C_BINARY, (SQLPOINTER)p_buf, buf_size, &indicator);
                    SIMPLEODBC_ASSERT(ret == SQL_SUCCESS, "SQLGetData() must returns SQL_SUCCESS, instead it returns " << ret);
                    SIMPLEODBC_ASSERT((size_t)indicator/ sizeof(SQLCHAR) == lengthRemained, "indicator (" << indicator << ") is not what's expected (" << lengthRemained << ")");
                    void* dest = reinterpret_cast<char*>(v.data()) + (buffLen * sizeof(SQLCHAR));
                    memcpy(dest, p_buf, lengthRemained * sizeof(SQLCHAR));
                    free(p_buf);
                    p_buf = nullptr;
                }
                else {  // totalDataLength <= buffLen
                    memcpy(v.data(), varbinaryData, totalDataLength * sizeof(SQLCHAR));
                }
                return byte_array_or_null(std::move(v));
            }
        }
        string_or_null columnValueImpl(
            const column_info& ci
        ) const {
            if (ci.is_wchar_type() || ci.is_unknown_type()) {
                auto v = column_value_as_string_impl<basic_string_value_traits<SQLWCHAR>>(ci.colNumber);
                string_or_null ret(v.is_null);
                if (!v.is_null) {
                    std::string utf8_s;
                    auto sizeof_SQLWCHAR = sizeof(SQLWCHAR);
                    if (sizeof_SQLWCHAR == 2) {
                        std::u16string u16(v.val.begin(), v.val.end());
                        utf8_s = ww898::utf::conv<char>(u16);
                    }
                    else if (sizeof_SQLWCHAR == 4) {
                        std::u32string u32(v.val.begin(), v.val.end());
                        utf8_s = ww898::utf::conv<char>(u32);
                    }
                    else {
                        SIMPLEODBC_FAIL("sizeof(SQLWCHAR) (=" << sizeof_SQLWCHAR << ") is not suppoted, only 2 and 4 are supported");
                    }
                    ret.val = utf8_s;
                }
                return ret;
            }
            else if (ci.is_buffer_type()) {
                auto v = get_binary_data_column_value(ci.colNumber);
                string_or_null ret(v.is_null);
                if (!v.is_null) {
                    std::ostringstream oss;
                    oss << "{" << "\"type\":\"Buffer\",\"data\":";
                    nlohmann::json j_arr = nlohmann::json::array();
                    for (const auto& byte : v.val) {
                        j_arr.push_back(byte);
                    }
                    auto json_array = j_arr.dump();
                    oss << json_array;
                    oss << "}";
                    auto json = oss.str();
                    ret.val = json;
                }
                return ret;
            }
            else {
                auto v = column_value_as_string_impl<basic_string_value_traits<SQLCHAR>>(ci.colNumber);
                string_or_null ret(v.is_null);
                if (!v.is_null) {
                    std::string val(v.val.begin(), v.val.end());
                    if (ci.dataType == SQL_BIT) {
                        val = (val == "0" ? "false" : "true");
                    }
                    ret.val = val;
                }
                return ret;
            }
        }
        cursor(SQLHSTMT hStmt)
            : hStmt_(hStmt)
        {
            SIMPLEODBC_ASSERT(hStmt != nullptr, "handle to the odbc statement object is null");
            getColumnInfos();
        }
    public:
        bool valid() const {
            return (hStmt_ != nullptr);
        }
        SQLHSTMT native_handle() const {
            return hStmt_;
        }
        operator SQLHSTMT() const {
            return hStmt_;
        }
        bool fetch_one() const {
            requireValid();
            fetched_row_.clear();
            auto fetched = (SQLFetch(hStmt_) == SQL_SUCCESS);
            if (fetched) {
                for (const auto& ci : column_infos_) {
                    try {
                        fetched_row_[ci.name] = columnValueImpl(ci);
                    }
                    catch (const std::exception& e) {
                        SIMPLEODBC_FAIL("error retrieving value for column '" << ci.name << "': " << e.what());
                    }
                }
            }
            return fetched;
        }
        bool next_result() const {
            requireValid();
            fetched_row_.clear();
            auto moved = (SQLMoreResults(hStmt_) == SQL_SUCCESS);
            if (moved) {
                getColumnInfos();
            }
            return moved;
        }
        size_t numColumns() const {
            return column_infos_.size();
        }
        const std::vector<column_info>& column_Infos() const {
            return column_infos_;
        }
        const column_info& col_info(
            const std::string& colName
        ) const {
            auto index = columnIndex(colName);
            return column_infos_[index];
        }
        const SQLSMALLINT& col_number(
            const std::string& colName
        ) const {
            return col_info(colName).colNumber;
        }
        // column value extraction operator
        string_or_null operator [](
            const std::string& colName
        ) const {
            requireValid();
            columnIndex(colName);
            auto it = fetched_row_.find(colName);
            SIMPLEODBC_REQUIRE(it != fetched_row_.end(), "end of recordset (EOF)");
            const auto& value = it->second;
            return value;
        }
        friend class statement; // only a statement object can construct a cursor object
    };
        
    class statement : public odbc_resurce {
    private:
        SQLHSTMT hStmt_;
    private:
        void checkError(
            SQLRETURN ret
        ) const {
            checkHandleError(ret, hStmt_, SQL_HANDLE_STMT);
        }
        void requireValid() const {
            SIMPLEODBC_REQUIRE(valid(), "not a valid odbc statement object");
        }
        statement(
            SQLHDBC hDbc
        ) : hStmt_(nullptr)
        {
            SIMPLEODBC_ASSERT(hDbc != nullptr, "handle to the odbc connection object is null");
            // Allocate statement handle
            auto ret = SQLAllocHandle(SQL_HANDLE_STMT, hDbc, &hStmt_);
            checkError(ret);
        }
    public:
        // moving constructor
        statement(statement&& src) noexcept {
            hStmt_ = src.detach();
        }
        // moving equal operator
        statement& operator= (statement&& rhs) {
            if (&rhs != this) {
                freeIfValid();
                hStmt_ = rhs.detach();
            }
            return *this;
        }
        SQLHSTMT detach() {
            SQLHSTMT ret = hStmt_;
            hStmt_ = nullptr;
            return ret;
        }
        bool valid() const {
            return (hStmt_ != nullptr);
        }
        SQLHSTMT native_handle() const {
            return hStmt_;
        }
        operator SQLHSTMT() const {
            return hStmt_;
        }
        void free() {
            requireValid();
            SQLFreeHandle(SQL_HANDLE_STMT, hStmt_);
            hStmt_ = nullptr;
        }
        cursor execute(
            const std::string& sql
        ) const {
            requireValid();
            // Execute a simple query
            auto ret = SQLExecDirect(hStmt_, (SQLCHAR*)sql.c_str(), SQL_NTS);
            checkError(ret);
            return cursor(hStmt_);
        }
    private:
        void freeIfValid() {
            if (valid()) {
                free();
            }
        }
    public:
        ~statement() {
            freeIfValid();
        }
        friend class connection; // only a connection object can construct a statement object
    };

    class connection: public odbc_resurce {
    private:
        SQLHENV hEnv_;
        SQLHDBC hDbc_;
    private:
        void checkError(
            SQLRETURN ret
        ) const {
            checkHandleError(ret, hDbc_, SQL_HANDLE_DBC);
        }
        void requireConnected() const {
            SIMPLEODBC_REQUIRE(connected(), "the odbc connection is currently not connected");
        }
    public:
        connection(
            const std::string& connectString
        ) :
            hEnv_(nullptr),
            hDbc_(nullptr)
        {
            bool connected = false;
            try {
                auto ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &hEnv_);
                checkHandleError(ret, hEnv_, SQL_HANDLE_ENV);
                // Set the ODBC version environment attribute
                ret = SQLSetEnvAttr(hEnv_, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
                checkHandleError(ret, hEnv_, SQL_HANDLE_ENV);
                // Allocate connection handle
                ret = SQLAllocHandle(SQL_HANDLE_DBC, hEnv_, &hDbc_);
                checkError(ret);
                // Connect to the database
                auto connStr = (SQLCHAR*)(connectString.c_str());
                ret = SQLDriverConnect(hDbc_, NULL, connStr, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
                checkError(ret);
                connected = true;
            }
            catch (...) {
                if (hDbc_ != nullptr) {
                    if (connected) {
                        SQLDisconnect(hDbc_);
                    }
                    SQLFreeHandle(SQL_HANDLE_DBC, hDbc_);
                    hDbc_ = nullptr;
                }
                if (hEnv_ != nullptr) {
                    SQLFreeHandle(SQL_HANDLE_ENV, hEnv_);
                    hEnv_ = nullptr;
                }
                throw;
            }
        }
        // moving constructor
        connection(connection&& src) noexcept {
            auto pr = src.detach();
            hEnv_ = pr.first;
            hDbc_ = pr.second;
        }
        // moving equal operator
        connection& operator= (connection&& rhs) {
            if (&rhs != this) {
                disconnectIfConnected();
                auto pr = rhs.detach();
                hEnv_ = pr.first;
                hDbc_ = pr.second;
            }
            return *this;
        }
        bool connected() const {
            return (hEnv_ != nullptr && hDbc_ != nullptr);
        }
        statement createStatement() const  {
            requireConnected();
            return statement(*this);
        }
        SQLHDBC native_handle() const {
            return hDbc_;
        }
        operator SQLHDBC() const {
            return hDbc_;
        }
        std::string getConnectionInfo(SQLUSMALLINT infoType, const std::string& info_desc) const {
            requireConnected();
            SQLCHAR buff[500];
            SQLSMALLINT len = 0;
            auto ret = SQLGetInfo(hDbc_, infoType, buff, sizeof(buff), &len);
            checkError(ret);
            SIMPLEODBC_ASSERT(len < sizeof(buff) / sizeof(buff[0]), info_desc << "'s length (" << len << ") << is too long");
            auto sz = (const char*)buff;
            return sz;
        }
        std::string getDriverName() const {
            return getConnectionInfo(SQL_DRIVER_NAME, "odbc driver name");
        }
        std::string getDriverVersion() const {
            return getConnectionInfo(SQL_DRIVER_VER, "odbc driver version");
        }
        std::string getODBCVersion() const {
            return getConnectionInfo(SQL_ODBC_VER, "odbc version");
        }
        std::pair<SQLHENV, SQLHDBC> detach() {
            std::pair<SQLHENV, SQLHDBC> ret(hEnv_, hDbc_);
            hEnv_ = nullptr;
            hDbc_ = nullptr;
            return ret;
        }
        void disconnect() {
            requireConnected();
            // Disconnect and free connection handle
            SQLDisconnect(hDbc_);
            SQLFreeHandle(SQL_HANDLE_DBC, hDbc_);
            // Free environment handle
            SQLFreeHandle(SQL_HANDLE_ENV, hEnv_);
            hEnv_ = nullptr;
            hDbc_ = nullptr;
        }
    private:
        void disconnectIfConnected() {
            if (connected()) {
                disconnect();
            }
        }
    public:
        ~connection() {
            disconnectIfConnected();
        }
    };
}
