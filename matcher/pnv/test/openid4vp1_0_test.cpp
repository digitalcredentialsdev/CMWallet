#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "common.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <sstream>

extern "C" int openid_main();

TEST_CASE("OpenID4VP")
{
    using namespace std::string_literals;

    SUBCASE("Only filter by phone number")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().credentials_buffer =
            makeRegistryBlob(loadDefaultRegistryJson());
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321", "+16502154322", "+16502154323"})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().entries.size() == 16);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        REQUIRE(TestCredmanState::instance().entries[1].cred_id == "verify_3");
        REQUIRE(TestCredmanState::instance().entries[2].cred_id == "verify_5");

        REQUIRE(TestCredmanState::instance().entries[8].cred_id == "verify_2");
        REQUIRE(TestCredmanState::instance().entries[9].cred_id == "verify_4");
        REQUIRE(TestCredmanState::instance().entries[10].cred_id == "verify_6");
    }

    SUBCASE("Filter by both carrier and android carrier hint requiring both matches")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().credentials_buffer =
            makeRegistryBlob(loadDefaultRegistryJson());
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_android_carrier_hint({11, 22, 33})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().entries.size() == 16);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_7");
        REQUIRE(TestCredmanState::instance().entries[1].cred_id == "verify_8");
        REQUIRE(TestCredmanState::instance().entries[2].cred_id == "verify_15");
    }

    SUBCASE("Filter by carrier only")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().credentials_buffer =
            makeRegistryBlob(loadDefaultRegistryJson());
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_vct_values({"number-verification/phone_number/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().entries.size() == 16);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "phone_number_5");
        REQUIRE(TestCredmanState::instance().entries[1].cred_id == "phone_number_6");
        REQUIRE(TestCredmanState::instance().entries[2].cred_id == "phone_number_7");
    }

    SUBCASE("Filter by both carrier and subscription hint ordering carrier matches first")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().credentials_buffer =
            makeRegistryBlob(loadDefaultRegistryJson());
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_subscription_hint({11, 22, 33})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() == 16);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_13");
        REQUIRE(TestCredmanState::instance().entries[1].cred_id == "verify_14");
        REQUIRE(TestCredmanState::instance().entries[2].cred_id == "verify_15");
        REQUIRE(TestCredmanState::instance().entries[4].cred_id == "verify_5");
    }

    SUBCASE("Full match with delegation_type 1 and wasm_version >= 7 sets delegation")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0]["delegation_type"] = 1;
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(reg);
        TestCredmanState::instance().wasm_version = 7;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321"})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() >= 1);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 1);
        // Verify an entry without delegation_type 1 does not have delegation set
        CHECK_EQ(TestCredmanState::instance().entries[1].delegation_type, 0);
    }

    SUBCASE("Full match with delegation_type 0 does not set delegation")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0]["delegation_type"] = 0;
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(reg);
        TestCredmanState::instance().wasm_version = 7;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321"})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() >= 1);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 0);
    }

    SUBCASE("Full match with delegation_type 1 but user verification requested overrides delegation to 0")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0]["delegation_type"] = 1;
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(reg);
        TestCredmanState::instance().wasm_version = 7;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321"})
                .with_vct_values({"number-verification/verify/ts43"})
                .with_user_verification("required")
                .build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() >= 1);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 0);
    }

    SUBCASE("Full match with delegation_type 1 but user_verification_hint claim requested overrides delegation to 0")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0]["delegation_type"] = 1;
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(reg);
        TestCredmanState::instance().wasm_version = 7;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321"})
                .with_vct_values({"number-verification/verify/ts43"})
                .with_user_verification_hint_claim()
                .build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() >= 1);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 0);
    }

    SUBCASE("Full match with delegation_type 1 but wasm_version < 7 does not set delegation")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0]["delegation_type"] = 1;
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(reg);
        TestCredmanState::instance().wasm_version = 6;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321"})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() >= 1);
        REQUIRE(TestCredmanState::instance().entries[0].cred_id == "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 0);
    }

    SUBCASE("Partial match with delegation_type 1 is allowed and sets delegation")
    {
        TestCredmanStateGuard guard;
        // Construct registry with one single entry that has delegation_type 1
        auto reg = loadDefaultRegistryJson();
        auto verify_1 = reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0];
        verify_1["delegation_type"] = 1;
        nlohmann::json single_reg = {
            {"credentials", {
                {"dc-authorization+sd-jwt", {
                    {"number-verification/verify/ts43", nlohmann::json::array({verify_1})}
                }}
            }}
        };
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(single_reg);
        TestCredmanState::instance().wasm_version = 7;

        // Build request with a credential set requiring 2 credentials, but only 1 matches
        RequestGenerator gen;
        gen.with_phone_number_hint({"+16502154321"});
        gen.with_vct_values({"number-verification/verify/ts43"});
        gen.add_credential({
            {"id", "cred_unmatched"},
            {"format", "dc-authorization+sd-jwt"},
            {"meta", {
                {"credential_authorization_jwt", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkY2FnZ3JlZ2F0b3IuZGV2In0.c2ln"},
                {"vct_values", nlohmann::json::array({"number-verification/unmatched"})}
            }}
        });
        gen.with_credential_sets(nlohmann::json::array({
            {
                {"required", true},
                {"options", nlohmann::json::array({
                    nlohmann::json::array({"aggregator1", "cred_unmatched"})
                })}
            }
        }));
        TestCredmanState::instance().request_buffer = gen.build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().entries.size() == 1);
        CHECK_EQ(TestCredmanState::instance().entries[0].cred_id, "verify_1");
        CHECK_EQ(TestCredmanState::instance().entries[0].delegation_type, 1);
    }

    SUBCASE("Partial match with delegation_type 0 is suppressed")
    {
        TestCredmanStateGuard guard;
        // Construct registry with one single entry that has delegation_type 0
        auto reg = loadDefaultRegistryJson();
        auto verify_1 = reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0];
        verify_1["delegation_type"] = 0;
        nlohmann::json single_reg = {
            {"credentials", {
                {"dc-authorization+sd-jwt", {
                    {"number-verification/verify/ts43", nlohmann::json::array({verify_1})}
                }}
            }}
        };
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(single_reg);
        TestCredmanState::instance().wasm_version = 7;

        RequestGenerator gen;
        gen.with_phone_number_hint({"+16502154321"});
        gen.with_vct_values({"number-verification/verify/ts43"});
        gen.add_credential({
            {"id", "cred_unmatched"},
            {"format", "dc-authorization+sd-jwt"},
            {"meta", {
                {"credential_authorization_jwt", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkY2FnZ3JlZ2F0b3IuZGV2In0.c2ln"},
                {"vct_values", nlohmann::json::array({"number-verification/unmatched"})}
            }}
        });
        gen.with_credential_sets(nlohmann::json::array({
            {
                {"required", true},
                {"options", nlohmann::json::array({
                    nlohmann::json::array({"aggregator1", "cred_unmatched"})
                })}
            }
        }));
        TestCredmanState::instance().request_buffer = gen.build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        // Option must be suppressed
        CHECK(TestCredmanState::instance().entries.empty());
    }

    SUBCASE("Partial match with delegation_type 1 but user verification requested is suppressed")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        auto verify_1 = reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0];
        verify_1["delegation_type"] = 1;
        nlohmann::json single_reg = {
            {"credentials", {
                {"dc-authorization+sd-jwt", {
                    {"number-verification/verify/ts43", nlohmann::json::array({verify_1})}
                }}
            }}
        };
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(single_reg);
        TestCredmanState::instance().wasm_version = 7;

        RequestGenerator gen;
        gen.with_phone_number_hint({"+16502154321"});
        gen.with_vct_values({"number-verification/verify/ts43"});
        gen.with_user_verification("required");
        gen.add_credential({
            {"id", "cred_unmatched"},
            {"format", "dc-authorization+sd-jwt"},
            {"meta", {
                {"credential_authorization_jwt", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkY2FnZ3JlZ2F0b3IuZGV2In0.c2ln"},
                {"vct_values", nlohmann::json::array({"number-verification/unmatched"})}
            }}
        });
        gen.with_credential_sets(nlohmann::json::array({
            {
                {"required", true},
                {"options", nlohmann::json::array({
                    nlohmann::json::array({"aggregator1", "cred_unmatched"})
                })}
            }
        }));
        TestCredmanState::instance().request_buffer = gen.build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        CHECK(TestCredmanState::instance().entries.empty());
    }

    SUBCASE("Partial match with delegation_type 1 but user_verification_hint claim requested is suppressed")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        auto verify_1 = reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0];
        verify_1["delegation_type"] = 1;
        nlohmann::json single_reg = {
            {"credentials", {
                {"dc-authorization+sd-jwt", {
                    {"number-verification/verify/ts43", nlohmann::json::array({verify_1})}
                }}
            }}
        };
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(single_reg);
        TestCredmanState::instance().wasm_version = 7;

        RequestGenerator gen;
        gen.with_phone_number_hint({"+16502154321"});
        gen.with_vct_values({"number-verification/verify/ts43"});
        gen.with_user_verification_hint_claim();
        gen.add_credential({
            {"id", "cred_unmatched"},
            {"format", "dc-authorization+sd-jwt"},
            {"meta", {
                {"credential_authorization_jwt", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkY2FnZ3JlZ2F0b3IuZGV2In0.c2ln"},
                {"vct_values", nlohmann::json::array({"number-verification/unmatched"})}
            }}
        });
        gen.with_credential_sets(nlohmann::json::array({
            {
                {"required", true},
                {"options", nlohmann::json::array({
                    nlohmann::json::array({"aggregator1", "cred_unmatched"})
                })}
            }
        }));
        TestCredmanState::instance().request_buffer = gen.build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        CHECK(TestCredmanState::instance().entries.empty());
    }

    SUBCASE("Partial match with delegation_type 1 but wasm_version < 7 is suppressed")
    {
        TestCredmanStateGuard guard;
        auto reg = loadDefaultRegistryJson();
        auto verify_1 = reg["credentials"]["dc-authorization+sd-jwt"]["number-verification/verify/ts43"][0];
        verify_1["delegation_type"] = 1;
        nlohmann::json single_reg = {
            {"credentials", {
                {"dc-authorization+sd-jwt", {
                    {"number-verification/verify/ts43", nlohmann::json::array({verify_1})}
                }}
            }}
        };
        TestCredmanState::instance().credentials_buffer = makeRegistryBlob(single_reg);
        TestCredmanState::instance().wasm_version = 6;

        RequestGenerator gen;
        gen.with_phone_number_hint({"+16502154321"});
        gen.with_vct_values({"number-verification/verify/ts43"});
        gen.add_credential({
            {"id", "cred_unmatched"},
            {"format", "dc-authorization+sd-jwt"},
            {"meta", {
                {"credential_authorization_jwt", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkY2FnZ3JlZ2F0b3IuZGV2In0.c2ln"},
                {"vct_values", nlohmann::json::array({"number-verification/unmatched"})}
            }}
        });
        gen.with_credential_sets(nlohmann::json::array({
            {
                {"required", true},
                {"options", nlohmann::json::array({
                    nlohmann::json::array({"aggregator1", "cred_unmatched"})
                })}
            }
        }));
        TestCredmanState::instance().request_buffer = gen.build();

        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        CHECK(TestCredmanState::instance().entries.empty());
    }
}
