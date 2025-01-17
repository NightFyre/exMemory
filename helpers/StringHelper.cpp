#include "StringHelper.h"

//---------------------------------------------------------------------------------------------------
std::string StringHelper::ToLower(const std::string& input)
{
    std::string result;
    for (auto c : input)
        result += tolower(c);
    return result;
};

//---------------------------------------------------------------------------------------------------
std::string StringHelper::ToUpper(const std::string& input)
{
    std::string result;
    for (auto c : input)
        result += toupper(c);
    return result;
};

//---------------------------------------------------------------------------------------------------
std::string StringHelper::ToString(const std::wstring& input) { return std::string(input.begin(), input.end()); }

//---------------------------------------------------------------------------------------------------
std::wstring StringHelper::ToWString(const std::string& input) { return std::wstring(input.begin(), input.end()); }