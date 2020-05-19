/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/testing/tester.hpp>

#include "eosio.system_tester.hpp"

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>

#include <boost/test/unit_test.hpp>

#include <contracts.hpp>

#ifdef NON_VALIDATING_TEST
#define TESTER tester
#else
#define TESTER validating_tester
#endif

namespace
{
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

struct genesis_account
{
   account_name name;
   uint64_t initial_balance;
};

struct create_attribute_t
{
   name attr_name;
   int32_t type;
   int32_t privacy_type;
};

class gift_resources_tester : public TESTER
{
public:
   gift_resources_tester();

   void deploy_contract(bool call_init = true)
   {
      set_code(config::system_account_name, contracts::rem_system_wasm());
      set_abi(config::system_account_name, contracts::rem_system_abi().data());
      if (call_init)
      {
         base_tester::push_action(config::system_account_name, N(init),
                                  config::system_account_name, mutable_variant_object()("version", 0)("core", CORE_SYM_STR));
      }

      const auto& accnt = control->db().get<account_object,by_name>( config::system_account_name );
      abi_def abi;
      BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi), true);
      rem_sys_abi_ser.set_abi(abi, abi_serializer::create_yield_function( abi_serializer_max_time ));
   }

   auto delegate_bandwidth(name from, name receiver, asset stake_quantity, uint8_t transfer = 1)
   {
      auto r = base_tester::push_action(config::system_account_name, N(delegatebw), from, mvo()("from", from)("receiver", receiver)("stake_quantity", stake_quantity)("transfer", transfer));
      produce_block();
      return r;
   }

   void create_currency(name contract, name manager, asset maxsupply, const private_key_type *signer = nullptr)
   {
      auto act = mutable_variant_object()("issuer", manager)("maximum_supply", maxsupply);

      base_tester::push_action(contract, N(create), contract, act);
   }

   auto issue(name contract, name manager, name to, asset amount)
   {
      auto r = base_tester::push_action(contract, N(issue), manager, mutable_variant_object()("to", to)("quantity", amount)("memo", ""));
      produce_block();
      return r;
   }

   auto set_privileged(name account)
   {
      auto r = base_tester::push_action(config::system_account_name, N(setpriv), config::system_account_name, mvo()("account", account)("is_priv", 1));
      produce_block();
      return r;
   }

   fc::variant get_global_state()
   {
      vector<char> data = get_row_by_account(config::system_account_name, config::system_account_name, N(global), N(global));
      if (data.empty())
      {
         std::cout << "\nData is empty\n"
                   << std::endl;
      }
      return data.empty() ? fc::variant() : rem_sys_abi_ser.binary_to_variant("eosio_global_state", data, abi_serializer::create_yield_function( abi_serializer_max_time ));
   }

   fc::variant get_total_stake(const account_name &act)
   {
      vector<char> data = get_row_by_account(config::system_account_name, act, N(userres), act);
      return data.empty() ? fc::variant() : rem_sys_abi_ser.binary_to_variant("user_resources", data, abi_serializer::create_yield_function( abi_serializer_max_time ));
   }

   transaction_trace_ptr create_account_with_resources(account_name new_acc, account_name creator, asset stake, bool transfer = true)
   {
      signed_transaction trx;
      set_transaction_headers(trx);

      authority owner_auth = authority(get_public_key(new_acc, "owner"));

      trx.actions.emplace_back(vector<permission_level>{{creator, config::active_name}},
                               newaccount{
                                   .creator = creator,
                                   .name = new_acc,
                                   .owner = owner_auth,
                                   .active = authority(get_public_key(new_acc, "active"))});

      trx.actions.emplace_back(
         get_action(config::system_account_name, N(delegatebw), vector<permission_level>{{creator, config::active_name}},
                     mvo()("from", creator)("receiver", new_acc)("stake_quantity", stake)("transfer", transfer)
         )
      );

      set_transaction_headers(trx);
      trx.sign(get_private_key(creator, "active"), control->get_chain_id());
      return push_transaction(trx);
   }

   auto create_attr(name attr, int32_t type, int32_t ptype)
   {
      auto r = base_tester::push_action(N(rem.attr), N(create), N(rem.attr), mvo()("attribute_name", attr)("type", type)("ptype", ptype));
      produce_block();
      return r;
   }

   auto set_attr(name issuer, name receiver, name attribute_name, std::string value)
   {
      auto r = base_tester::push_action(N(rem.attr), N(setattr), issuer, mvo()("issuer", issuer)("receiver", receiver)("attribute_name", attribute_name)("value", value));
      produce_block();
      return r;
   }

   auto unset_attr(name issuer, name receiver, name attribute_name)
   {
      auto r = base_tester::push_action(N(rem.attr), N(unsetattr), issuer, mvo()("issuer", issuer)("receiver", receiver)("attribute_name", attribute_name));
      produce_block();
      return r;
   }

   fc::variant get_attribute_info(const account_name &attribute)
   {
      vector<char> data = get_row_by_account(N(rem.attr), N(rem.attr), N(attrinfo), attribute);
      if (data.empty())
      {
         return fc::variant();
      }
      return rem_attr_abi_ser.binary_to_variant("attribute_info", data, abi_serializer::create_yield_function( abi_serializer_max_time ));
   }

   fc::variant get_account_attribute(const account_name &issuer, const account_name &account, const account_name &attribute)
   {
      const auto &db = control->db();
      const auto *t_id = db.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(N(rem.attr), attribute, N(attributes)));
      if (!t_id)
      {
         return fc::variant();
      }

      const auto &idx = db.get_index<chain::key_value_index, chain::by_scope_primary>();

      vector<char> data;
      for (auto it = idx.lower_bound(boost::make_tuple(t_id->id, 0)); it != idx.end() && it->t_id == t_id->id; it++)
      {
         if (it->value.empty())
         {
            continue;
         }
         data.resize(it->value.size());
         memcpy(data.data(), it->value.data(), data.size());

         const auto attr_obj = rem_attr_abi_ser.binary_to_variant("attribute_data", data, abi_serializer::create_yield_function( abi_serializer_max_time ));
         if (attr_obj["receiver"].as_string() == account.to_string() &&
             attr_obj["issuer"].as_string() == issuer.to_string())
         {
            return attr_obj["attribute"];
         }
      }

      return fc::variant();
   }

   asset get_balance(const account_name &act)
   {
      return get_currency_balance(N(rem.token), symbol(CORE_SYMBOL), act);
   }

   variant get_remprice_tbl( const name& pair )
   {
      vector<char> data = get_row_by_account( N(rem.oracle), N(rem.oracle), N(remprice), pair );
      return data.empty() ? fc::variant() : rem_oracle_abi_ser.binary_to_variant( "remprice", data, abi_serializer::create_yield_function( abi_serializer_max_time ) );
   }

   auto register_producer(name producer)
   {
      auto r = base_tester::push_action(config::system_account_name, N(regproducer), producer, mvo()
         ("producer",  name(producer))
         ("producer_key", get_public_key( producer, "active" ) )
         ("url", "" )
         ("location", 0 )
      );
      produce_block();
      return r;
   }

   void votepro(account_name voter, vector<account_name> producers)
   {
      std::sort( producers.begin(), producers.end() );
      base_tester::push_action(config::system_account_name, N(voteproducer), voter, mvo()
         ("voter", name(voter))
         ("proxy", name(0) )
         ("producers", producers)
      );
      produce_blocks();
   };

   auto updateauth(const name &account, const name& code_account)
   {
      auto auth = authority(get_public_key(account, "active"));
      auth.accounts.push_back(permission_level_weight{{code_account, config::rem_code_name}, 1});

      auto r = base_tester::push_action(N(rem), N(updateauth), account, mvo()
         ("account", account.to_string())
         ("permission", "active")
         ("parent", "owner")
         ("auth", auth)
      );
      produce_blocks();
      return r;
   }

   auto addpair(const name& pair, const vector<permission_level>& level)
   {
      auto r = base_tester::push_action(N(rem.oracle), N(addpair), level, mvo()
         ("pair", pair )
      );
      produce_block();
      return r;
   }

   auto setprice(const name& producer, std::map<name, double> &pairs_data) {
      auto r = base_tester::push_action(N(rem.oracle), N(setprice), producer, mvo()
         ("producer",  name(producer))
         ("pairs_data", pairs_data )
      );
      produce_block();
      return r;
   }

   auto setminstake(const uint64_t& min_account_stake) {
      auto r = base_tester::push_action(config::system_account_name, N(setminstake), config::system_account_name, mvo()
         ("min_account_stake",  min_account_stake)
      );
      produce_block();
      return r;
   }

   void set_code_abi(const account_name &account, const vector<uint8_t> &wasm, const char *abi, const private_key_type *signer = nullptr)
   {
      wdump((account));
      set_code(account, wasm, signer);
      set_abi(account, abi, signer);
      if (account == N(rem.attr))
      {
         const auto &accnt = control->db().get<account_object, by_name>(account);
         abi_def abi_definition;
         BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi_definition), true);
         rem_attr_abi_ser.set_abi(abi_definition, abi_serializer::create_yield_function( abi_serializer_max_time ));
      }
      else if (account == N(rem.oracle))
      {
         const auto &accnt = control->db().get<account_object, by_name>(account);
         abi_def abi_definition;
         BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi_definition), true);
         rem_oracle_abi_ser.set_abi(abi_definition, abi_serializer::create_yield_function( abi_serializer_max_time ));
      }
      produce_blocks();
   }

   void transfer(name from, name to, const asset &amount, name manager = config::system_account_name)
   {
      base_tester::push_action(N(rem.token), N(transfer), manager, mutable_variant_object()("from", from)("to", to)("quantity", amount)("memo", ""));
      produce_blocks();
   }

   void print_usage(account_name account)
   {
      auto rlm = control->get_resource_limits_manager();
      auto ram_usage = rlm.get_account_ram_usage(account);
      int64_t ram_bytes;
      int64_t net_weight;
      int64_t cpu_weight;
      rlm.get_account_limits(account, ram_bytes, net_weight, cpu_weight);
      const auto free_bytes = ram_bytes - ram_usage;
      wdump((account)(ram_usage)(free_bytes)(ram_bytes)(net_weight)(cpu_weight));
   }

   abi_serializer rem_attr_abi_ser;
   abi_serializer rem_sys_abi_ser;
   abi_serializer rem_oracle_abi_ser;
};


gift_resources_tester::gift_resources_tester()
{
   create_accounts({N(rem.msig), N(rem.token), N(rem.rex), N(rem.ram),
                    N(rem.ramfee), N(rem.stake), N(rem.bpay), N(rem.oracle),
                    N(rem.spay), N(rem.vpay), N(rem.saving), N(rem.attr)});

   // Register producers
   const auto producer_candidates = {
      N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
      N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
      N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)
   };

   struct rem_genesis_account {
      account_name name;
      uint64_t     initial_balance;
   };

   std::vector<rem_genesis_account> genesis_test( {
     {N(b1),        100'000'000'0000ll},
     {N(whale1),     40'000'000'0000ll},
     {N(whale2),     30'000'000'0000ll},
     {N(whale3),     20'000'000'0000ll},
     {N(proda),         500'000'0000ll},
     {N(prodb),         500'000'0000ll},
     {N(prodc),         500'000'0000ll},
     {N(prodd),         500'000'0000ll},
     {N(prode),         500'000'0000ll},
     {N(prodf),         500'000'0000ll},
     {N(prodg),         500'000'0000ll},
     {N(prodh),         500'000'0000ll},
     {N(prodi),         500'000'0000ll},
     {N(prodj),         500'000'0000ll},
     {N(prodk),         500'000'0000ll},
     {N(prodl),         500'000'0000ll},
     {N(prodm),         500'000'0000ll},
     {N(prodn),         500'000'0000ll},
     {N(prodo),         500'000'0000ll},
     {N(prodp),         500'000'0000ll},
     {N(prodq),         500'000'0000ll},
     {N(prodr),         500'000'0000ll},
     {N(prods),         500'000'0000ll},
     {N(prodt),         500'000'0000ll},
     {N(produ),         500'000'0000ll},
     {N(runnerup1),     200'000'0000ll},
     {N(runnerup2),     150'000'0000ll},
     {N(runnerup3),     100'000'0000ll},
   });

   set_code_abi(N(rem.msig),
                contracts::rem_msig_wasm(),
                contracts::rem_msig_abi().data()); //, &rem_active_pk);
   set_code_abi(N(rem.token),
                  contracts::rem_token_wasm(),
                  contracts::rem_token_abi().data()); //, &rem_active_pk);
   set_code_abi(N(rem.attr),
                  contracts::rem_attr_wasm(),
                  contracts::rem_attr_abi().data()); //, &rem_active_pk);
   set_code_abi(N(rem.oracle),
                contracts::rem_oracle_wasm(),
                contracts::rem_oracle_abi().data()); //, &rem_active_pk);

   // Set privileged for rem.msig and rem.token
   set_privileged(N(rem.msig));
   set_privileged(N(rem.token));

   // Verify rem.msig and rem.token is privileged
   const auto &rem_msig_acc = get<account_metadata_object, by_name>(N(rem.msig));
   BOOST_TEST(rem_msig_acc.is_privileged() == true);
   const auto &rem_token_acc = get<account_metadata_object, by_name>(N(rem.token));
   BOOST_TEST(rem_token_acc.is_privileged() == true);

   // Create SYS tokens in rem.token, set its manager as rem
   auto max_supply = core_from_string("1000000000.0000");
   auto initial_supply = core_from_string("900000000.0000");
   create_currency(N(rem.token), config::system_account_name, max_supply);
   // Issue the genesis supply of 1 billion SYS tokens to rem.system
   issue(N(rem.token), config::system_account_name, config::system_account_name, initial_supply);

   auto actual = get_balance(config::system_account_name);
   BOOST_REQUIRE_EQUAL(initial_supply, actual);

   // Create genesis accounts
   for( const auto& account : genesis_test ) {
      create_account( account.name, config::system_account_name );
   }

   deploy_contract();

   // Buy ram and stake cpu and net for each genesis accounts
   for( const auto& account : genesis_test ) {
      const auto stake_quantity = account.initial_balance - 1000;

      const auto r = delegate_bandwidth(N(rem.stake), account.name, asset(stake_quantity));
      BOOST_REQUIRE( !r->except_ptr );
   }

   for( const auto& producer : producer_candidates ) {
      register_producer(producer);
   }

   const auto whales_as_producers = { N(b1), N(whale1), N(whale2) };
   for( const auto& producer : whales_as_producers ) {
      register_producer(producer);
   }

   votepro(N(whale1), { N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
                        N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
                        N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ) });
   votepro( N(whale2), { N(proda), N(prodb), N(prodc), N(prodd), N(prode) } );
   votepro( N(b1), { N(proda), N(prodb), N(prodc), N(prodd), N(prode) } );
   // set permission @rem.code to rem.oracle
   updateauth(N(rem.oracle), N(rem.oracle));

   // add new supported pairs to the rem.oracle
   vector<name> supported_pairs = {
      N(rem.usd), N(rem.eth), N(rem.btc),
   };
   for (const auto &pair : supported_pairs) {
      addpair(pair, { {N(rem.oracle), config::active_name} });
   }
   map<name, double> pair_rate {
      {N(rem.usd), 0.003210},
      {N(rem.btc), 0.0000003957},
      {N(rem.eth), 0.0000176688}
   };
   for( const auto& producer : control->head_block_state()->active_schedule.producers )
      setprice(producer.producer_name, pair_rate);
}

BOOST_AUTO_TEST_SUITE(rem_gift_resources_tests)

BOOST_FIXTURE_TEST_CASE(acc_creation_with_attr_set, gift_resources_tester)
{
   try
   {
      const auto min_account_stake = get_global_state()["min_account_stake"].as<int64_t>();
      BOOST_REQUIRE_EQUAL(min_account_stake, 1000000u);
      print_usage(N(rem));
      print_usage(N(rem.stake));

      const auto acc_gifter_attr_name = N(accgifter);

      // creating without transfer, should throw as `accgifter` attribute is not set for `rem`
      {
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name).is_null());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(testram11111), config::system_account_name, asset{min_account_stake}, false),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );
      }

      // create and set `accgifter` attribute to 100% for `rem`
      {
         const auto acc_gifter_attr = create_attribute_t{.attr_name = acc_gifter_attr_name, .type = 1, .privacy_type = 3};
         create_attr(acc_gifter_attr.attr_name, acc_gifter_attr.type, acc_gifter_attr.privacy_type);

         const auto attr_info = get_attribute_info(acc_gifter_attr.attr_name);
         BOOST_REQUIRE(acc_gifter_attr.attr_name.to_string() == attr_info["attribute_name"].as_string());
         BOOST_REQUIRE(acc_gifter_attr.type == attr_info["type"].as_int64());
         BOOST_REQUIRE(acc_gifter_attr.privacy_type == attr_info["ptype"].as_int64());

         // the length of hex string should be even number
         // 100% = 1000000 in decimal = 40420f00 in hex big-endian
         set_attr(N(rem.attr), config::system_account_name, acc_gifter_attr_name, "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name)["data"].as_string() == "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name)["pending"].as_string().empty());
      }

      // now `accgifter` attribute is set for `rem` so it can create acc with gifted resources
      {
         create_account_with_resources(N(testram11111), config::system_account_name, asset{min_account_stake}, false);

         const auto total_stake = get_total_stake(N(testram11111));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 0);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == min_account_stake);
      }

      // transfer resources to testram11111 so free_stake_amount is half covered
      {
         delegate_bandwidth(N(rem.stake), N(testram11111), asset(50'0000));

         const auto total_stake = get_total_stake(N(testram11111));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 50'0000);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 50'0000);
      }

      // set `accgifter` attribute to 100% for `testram11111` so it can create account with gifted resources
      {
         // fixes `no balance object found`
         transfer( config::system_account_name, N(testram11111), asset{ 10'000'0000 } );
         BOOST_REQUIRE( get_balance(N(testram11111)) == asset{ 10'000'0000 } );

         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         create_account_with_resources(N(testram22222), N(testram11111), asset{min_account_stake}, false);

         const auto total_stake = get_total_stake(N(testram22222));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 0);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == min_account_stake);
         BOOST_TEST( get_balance(N(testram11111)) == asset{ 9'900'0000 } );
      }

      // set `accgifter` attribute to 50% for `testram11111` so now it should pay 50% of min stake
      {
         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "20a10700");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "20a10700");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(testram33333), N(testram11111), asset{min_account_stake}, false),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );

         create_account_with_resources(N(testram33333), N(testram11111), asset{50'0000}, true);
         BOOST_TEST( get_balance(N(testram11111)) == asset{ 9'850'0000 } );

         const auto total_stake = get_total_stake(N(testram33333));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 50'0000);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 50'0000);
      }

      // set `accgifter` attribute to 20% for `testram11111` so now it should pay 80% of min stake
      {
         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "400d0300");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "400d0300");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(testram44444), N(testram11111), asset{50'0000}, true),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );

         create_account_with_resources(N(testram44444), N(testram11111), asset{80'0000}, true);
         BOOST_TEST( get_balance(N(testram11111)) == asset{ 9'770'0000 } );

         const auto total_stake = get_total_stake(N(testram44444));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 80'0000);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 20'0000);
      }

      // create account with more than 80'0000 own resources
      {
         {
            create_account_with_resources(N(testram55555), N(testram11111), asset{85'0000}, true);

            const auto total_stake = get_total_stake(N(testram55555));
            BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 85'0000);
            BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 15'0000);
         }
         {
            create_account_with_resources(N(testram12121), N(testram11111), asset{165'0000}, true);

            const auto total_stake = get_total_stake(N(testram12121));
            BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 165'0000);
            BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 0);
         }
      }

      // unset `accgifter` attribute to `testram11111`
      {
         unset_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name);
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name).is_null());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(invalid55555), N(testram11111), asset{min_account_stake}, false),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );
      }
   }
   FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE(acc_creation_with_attr_set_with_oracle_price, gift_resources_tester)
{
   try
   {
      // test account creation fee based on rem.oracle.
      // account_creation_fee = min(min_account_stake, min_account_price / rem_usd_price);
      // in this case min_account_stake > min_account_price / rem_usd_price
      setminstake(200'0000);

      auto min_account_stake_global = get_global_state()["min_account_stake"].as<int64_t>();
      const uint64_t min_account_price = 5000;
      BOOST_REQUIRE_EQUAL(min_account_stake_global, 2000000u);
      auto pair_data = get_remprice_tbl(N(rem.usd));
      print_usage(N(rem));
      print_usage(N(rem.stake));

      const auto acc_gifter_attr_name = N(accgifter);

      // creating without transfer, should throw as `accgifter` attribute is not set for `rem`
      {
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name).is_null());
         
         BOOST_REQUIRE_EXCEPTION(
               create_account_with_resources(N(testram11111), config::system_account_name, asset{min_account_stake_global}, false),
               eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );
      }

      // create and set `accgifter` attribute to 100% for `rem`
      {
         const auto acc_gifter_attr = create_attribute_t{.attr_name = acc_gifter_attr_name, .type = 1, .privacy_type = 3};
         create_attr(acc_gifter_attr.attr_name, acc_gifter_attr.type, acc_gifter_attr.privacy_type);
         
         const auto attr_info = get_attribute_info(acc_gifter_attr.attr_name);
         BOOST_REQUIRE(acc_gifter_attr.attr_name.to_string() == attr_info["attribute_name"].as_string());
         BOOST_REQUIRE(acc_gifter_attr.type == attr_info["type"].as_int64());
         BOOST_REQUIRE(acc_gifter_attr.privacy_type == attr_info["ptype"].as_int64());
         
         // the length of hex string should be even number
         // 100% = 1000000 in decimal = 40420f00 in hex big-endian
         set_attr(N(rem.attr), config::system_account_name, acc_gifter_attr_name, "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name)["data"].as_string() == "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), config::system_account_name, acc_gifter_attr_name)["pending"].as_string().empty());
      }

      // create account by oracle price, min_account_stake = 0.5 / 0.003210 = 155.7632 REM for 1 account
      int64_t min_account_stake = min_account_price / pair_data["price"].as_double();

      // now `accgifter` attribute is set for `rem` so it can create acc with gifted resources
      {
         create_account_with_resources(N(testram11111), config::system_account_name, asset{min_account_stake}, false);

         const auto total_stake = get_total_stake(N(testram11111));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 0);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == min_account_stake_global);
      }

      // transfer resources to testram11111 so free_stake_amount is half covered
      {
         delegate_bandwidth(N(rem.stake), N(testram11111), asset(min_account_stake / 2));

         const auto total_stake = get_total_stake(N(testram11111));
         uint64_t free_stake_amount = min_account_stake_global - (min_account_stake / 2);

         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == min_account_stake / 2);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() ==  free_stake_amount);
      }

      // set `accgifter` attribute to 100% for `testram11111` so it can create account with gifted resources
      {
         // fixes `no balance object found`
         transfer( config::system_account_name, N(testram11111), asset{ 10'000'0000 } );
         BOOST_REQUIRE( get_balance(N(testram11111)) == asset{ 10'000'0000 } );

         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "40420f00");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         create_account_with_resources(N(testram22222), N(testram11111), asset{min_account_stake}, false);

         const auto total_stake = get_total_stake(N(testram22222));
         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 0);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == min_account_stake_global);
         BOOST_TEST( get_balance(N(testram11111)) == asset{ 10'000'0000 } - asset(min_account_stake) );
      }

      // set `accgifter` attribute to 50% for `testram11111` so now it should pay 50% of min stake
      {
         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "20a10700");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "20a10700");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(testram33333), N(testram11111), asset{min_account_stake}, false),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );

         auto balance_before = get_balance(N(testram11111));
         // min_account_stake / 2 = 50 % min_account_stake
         create_account_with_resources(N(testram33333), N(testram11111), asset(min_account_stake / 2), true);
         auto balance_after = get_balance(N(testram11111));

         BOOST_TEST( balance_before - asset(min_account_stake / 2) == balance_after );

         const auto total_stake = get_total_stake(N(testram33333));
         uint64_t free_stake_amount = min_account_stake_global - (min_account_stake / 2);

         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == min_account_stake / 2);
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == free_stake_amount);
      }

      // set `accgifter` attribute to 20% for `testram11111` so now it should pay 80% of min stake
      {
         set_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name, "400d0300");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["data"].as_string() == "400d0300");
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name)["pending"].as_string().empty());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(testram44444), N(testram11111), asset{50'0000}, true),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );

         auto balance_before = get_balance(N(testram11111));
         // min_account_stake * 8 / 10 = 80 % min_account_stake + 0.0001 REM accuracy
         create_account_with_resources(N(testram44444), N(testram11111), asset((min_account_stake * 8 / 10) + 1), true);
         auto balance_after = get_balance(N(testram11111));
         BOOST_TEST( balance_before - asset((min_account_stake * 8 / 10) + 1) == balance_after );

         const auto total_stake = get_total_stake(N(testram44444));
         uint64_t free_stake_amount = min_account_stake_global - (min_account_stake * 8 / 10);

         BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == (min_account_stake * 8 / 10) + 1);
         // min_account_stake / 5 = 20 % min_account_stake
         BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == free_stake_amount - 1);
      }

      // create account with more than min_account_stake * 8 / 10 own resources
      {
         {
            // min_account_stake * 8 / 10 = 80 % min_account_stake + 5.0000 REM
            create_account_with_resources(N(testram55555), N(testram11111), asset((min_account_stake * 8 / 10) + 5'0000), true);

            const auto total_stake = get_total_stake(N(testram55555));
            uint64_t free_stake_amount = min_account_stake_global - (min_account_stake * 8 / 10) - 5'0000;

            BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == (min_account_stake * 8 / 10) + 5'0000);
            // min_account_stake / 5 = 20 % min_account_stake - 5.0000 REM
            BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == free_stake_amount);
         }
         {
            create_account_with_resources(N(testram12121), N(testram11111), asset{265'0000}, true);

            const auto total_stake = get_total_stake(N(testram12121));
            BOOST_TEST(total_stake["own_stake_amount"].as_uint64() == 265'0000);
            BOOST_TEST(total_stake["free_stake_amount"].as_uint64() == 0);
         }
      }

      // unset `accgifter` attribute to `testram11111`
      {
         unset_attr(N(rem.attr), N(testram11111), acc_gifter_attr_name);
         BOOST_REQUIRE(get_account_attribute(N(rem.attr), N(testram11111), acc_gifter_attr_name).is_null());

         BOOST_REQUIRE_EXCEPTION(
            create_account_with_resources(N(invalid55555), N(testram11111), asset{min_account_stake}, false),
            eosio_assert_message_exception, fc_exception_message_starts_with("assertion failure with message: insufficient minimal account stake")
         );
      }
   }
   FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace
