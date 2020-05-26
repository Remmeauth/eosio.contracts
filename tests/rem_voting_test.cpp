/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/testing/tester.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>

#include <boost/test/unit_test.hpp>

#include <contracts.hpp>

#ifdef NON_VALIDATING_TEST
#define TESTER tester
#else
#define TESTER validating_tester
#endif


using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

struct rem_genesis_account {
   account_name name;
   uint64_t     initial_balance;
};

std::vector<rem_genesis_account> rem_test_genesis( {
  {N(b1),        100'000'000'0000ll}, // TODO investigate why `b1` should be at least this value?
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

class voting_tester : public TESTER {
public:
   voting_tester();

   void deploy_contract( bool call_init = true ) {
      set_code( config::system_account_name, contracts::rem_system_wasm() );
      set_abi( config::system_account_name, contracts::rem_system_abi().data() );
      if( call_init ) {
         base_tester::push_action(config::system_account_name, N(init),
                                  config::system_account_name,  mutable_variant_object()
                                  ("version", 0)
                                  ("core", CORE_SYM_STR)
            );
      }
      const auto& accnt = control->db().get<account_object,by_name>( config::system_account_name );
      abi_def abi;
      BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi), true);
      abi_ser.set_abi(abi, abi_serializer::create_yield_function( abi_serializer_max_time ));
   }

   fc::variant get_global_state() {
      vector<char> data = get_row_by_account( config::system_account_name, config::system_account_name, N(global), N(global) );
      if (data.empty()) std::cout << "\nData is empty\n" << std::endl;
      return data.empty() ? fc::variant() : abi_ser.binary_to_variant( "eosio_global_state", data, abi_serializer::create_yield_function( abi_serializer_max_time ) );
   }

    auto delegate_bandwidth( name from, name receiver, asset stake_quantity, uint8_t transfer = 1) {
       auto r = base_tester::push_action(config::system_account_name, N(delegatebw), from, mvo()
                    ("from", from )
                    ("receiver", receiver)
                    ("stake_quantity", stake_quantity)
                    ("transfer", transfer)
                    );
       produce_block();
       return r;
    }

   auto undelegate_bandwidth( name from, name receiver, asset unstake_quantity ) {
       auto r = base_tester::push_action(config::system_account_name, N(undelegatebw), from, mvo()
                    ("from", from )
                    ("receiver", receiver)
                    ("unstake_quantity", unstake_quantity)
                    );
       produce_block();
       return r;
    }


    void create_currency( name contract, name manager, asset maxsupply, const private_key_type* signer = nullptr ) {
        auto act =  mutable_variant_object()
                ("issuer",       manager )
                ("maximum_supply", maxsupply );

        base_tester::push_action(contract, N(create), contract, act );
    }

    auto issue( name contract, name manager, name to, asset amount ) {
       auto r = base_tester::push_action( contract, N(issue), manager, mutable_variant_object()
                ("to",      to )
                ("quantity", amount )
                ("memo", "")
        );
        produce_block();
        return r;
    }

    auto transfer( name from, name to, asset quantity ) {
       auto r = push_action( N(rem.token), N(transfer), config::system_account_name,
                             mutable_variant_object()
                             ("from", from)
                             ("to", to)
                             ("quantity", quantity)
                             ("memo", "")
       );
       produce_block();

       return r;
    }

    auto torewards( name caller, name payer, asset amount ) {
        auto r = base_tester::push_action(config::system_account_name, N(torewards), caller, mvo()
                ("payer", payer)
                ("amount", amount)
        );
        produce_block();
        return r;
    }

    void set_lock_period(uint64_t mature_period ) {
        base_tester::push_action(config::system_account_name, N(setlockperiod),config::system_account_name,  mvo()("period_in_days", mature_period));
        produce_block();
    }

    void set_unlock_period(uint64_t mature_period ) {
        base_tester::push_action(config::system_account_name, N(setunloperiod),config::system_account_name,  mvo()("period_in_days", mature_period));
        produce_block();
    }

    auto claim_rewards( name owner ) {
       auto r = base_tester::push_action( config::system_account_name, N(claimrewards), owner, mvo()("owner",  owner ));
       produce_block();
       return r;
    }

    auto set_privileged( name account ) {
       auto r = base_tester::push_action(config::system_account_name, N(setpriv), config::system_account_name,  mvo()("account", account)("is_priv", 1));
       produce_block();
       return r;
    }

    auto register_producer(name producer) {
       auto r = base_tester::push_action(config::system_account_name, N(regproducer), producer, mvo()
                       ("producer",  name(producer))
                       ("producer_key", get_public_key( producer, "active" ) )
                       ("url", "" )
                       ("location", 0 )
                    );
       produce_block();
       return r;
    }

    asset get_balance( const account_name& act ) {
         return get_currency_balance(N(rem.token), symbol(CORE_SYMBOL), act);
    }

    void set_code_abi(const account_name& account, const vector<uint8_t>& wasm, const char* abi, const private_key_type* signer = nullptr) {
       wdump((account));
        set_code(account, wasm, signer);
        set_abi(account, abi, signer);
        if (account == config::system_account_name) {
           const auto& accnt = control->db().get<account_object,by_name>( account );
           abi_def abi_definition;
           BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi_definition), true);
           abi_ser.set_abi(abi_definition, abi_serializer::create_yield_function( abi_serializer_max_time ));
        }
        produce_blocks();
    }

    fc::variant get_producer_info( const account_name& act ) {
       vector<char> data = get_row_by_account( config::system_account_name, config::system_account_name, N(producers), act );
       return abi_ser.binary_to_variant( "producer_info", data, abi_serializer::create_yield_function( abi_serializer_max_time ) );
    }

    fc::variant get_voter_info( const account_name& act ) {
       vector<char> data = get_row_by_account( config::system_account_name, config::system_account_name, N(voters), act );
       return data.empty() ? fc::variant() : abi_ser.binary_to_variant( "voter_info", data, abi_serializer::create_yield_function( abi_serializer_max_time ) );
    }

   fc::variant get_refund_request( name account ) {
      vector<char> data = get_row_by_account( config::system_account_name, account, N(refunds), account );
      return data.empty() ? fc::variant() : abi_ser.binary_to_variant( "refund_request", data, abi_serializer::create_yield_function( abi_serializer_max_time ) );
   }

    // Vote for producers
    void votepro( account_name voter, vector<account_name> producers ) {
       std::sort( producers.begin(), producers.end() );
       base_tester::push_action(config::system_account_name, N(voteproducer), voter, mvo()
                            ("voter", name(voter))
                            ("proxy", name(0) )
                            ("producers", producers)
                );
       produce_blocks();
    };

   auto unregister_producer(name producer) {
       auto r = base_tester::push_action(config::system_account_name, N(unregprod), producer, mvo()
               ("producer",  name(producer))
               ("producer_key", get_public_key( producer, "active" ) )
               ("url", "" )
               ("location", 0 )
       );
       produce_block();
       return r;
   }

   auto refund( const name& to ) {
      auto r = base_tester::push_action(
         config::system_account_name, N(refund), to,
         mvo()("owner", to)
      );

      produce_block();
      return r;
   }

   auto refund_to_stake( const name& to ) {
      auto r = base_tester::push_action(
         config::system_account_name, N(refundtostake), to,
         mvo()("owner", to)
      );

      produce_block();
      return r;
   }

    fc::microseconds microseconds_since_epoch_of_iso_string( const fc::variant& v ) {
        return time_point::from_iso_string( v.as_string() ).time_since_epoch();
    }

    abi_serializer abi_ser;
};

voting_tester::voting_tester() {
   // Create rem.msig and rem.token
   create_accounts({N(rem.msig), N(rem.token), N(rem.rex), N(rem.ram),
                    N(rem.ramfee), N(rem.stake), N(rem.bpay),
                    N(rem.spay), N(rem.vpay), N(rem.saving)});

   // Set code for the following accounts:
   //  - rem (code: rem.bios) (already set by tester constructor)
   //  - rem.msig (code: rem.msig)
   //  - rem.token (code: rem.token)
   set_code_abi(N(rem.msig),
               contracts::rem_msig_wasm(),
               contracts::rem_msig_abi().data());//, &rem_active_pk);
   set_code_abi(N(rem.token),
               contracts::rem_token_wasm(),
               contracts::rem_token_abi().data()); //, &rem_active_pk);

   // Set privileged for rem.msig and rem.token
   set_privileged(N(rem.msig));
   set_privileged(N(rem.token));

   // Verify rem.msig and rem.token is privileged
   const auto& rem_msig_acc = get<account_metadata_object, by_name>(N(rem.msig));
   BOOST_TEST(rem_msig_acc.is_privileged() == true);
   const auto& rem_token_acc = get<account_metadata_object, by_name>(N(rem.token));
   BOOST_TEST(rem_token_acc.is_privileged() == true);

   // Create SYS tokens in rem.token, set its manager as rem
   const auto max_supply     = core_from_string("1000000000.0000"); /// 10x larger than 1B initial tokens
   const auto initial_supply = core_from_string("100000000.0000");  /// 10x larger than 1B initial tokens

   create_currency(N(rem.token), config::system_account_name, max_supply);
   // Issue the genesis supply of 1 billion SYS tokens to rem.system
   issue(N(rem.token), config::system_account_name, config::system_account_name, initial_supply);

   auto actual = get_balance(config::system_account_name);
   BOOST_REQUIRE_EQUAL(initial_supply, actual);

   // Create genesis accounts
   for( const auto& account : rem_test_genesis ) {
      create_account( account.name, config::system_account_name );
   }

   deploy_contract();

   // Buy ram and stake cpu and net for each genesis accounts
   for( const auto& account : rem_test_genesis ) {
      const auto stake_quantity = account.initial_balance - 1000;

      const auto r = delegate_bandwidth(N(rem.stake), account.name, asset(stake_quantity));
      BOOST_REQUIRE( !r->except_ptr );
   }
}

BOOST_AUTO_TEST_SUITE(rem_voting_tests)
BOOST_FIXTURE_TEST_CASE( rem_voting_test, voting_tester ) {
    try {
        // Register producers
        const auto producer_candidates = {
                N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
                N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
                N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)
        };
        for( const auto& producer : producer_candidates ) {
           register_producer(producer);
        }

        // Runners-up should not be able to register as producer because their stakes are less then producer threshold
        const auto producer_runnerups = {
                N(runnerup1), N(runnerup2), N(runnerup3)
        };
        // Now runnerups have enough stake to become producers
        for( const auto& producer : producer_runnerups ) {
           register_producer(producer);
        }

        votepro( N(whale1), {N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
                             N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
                             N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)} );
        votepro( N(whale2), {N(proda), N(prodb), N(prodc), N(prodd), N(prode)} );

        vector<char> data = get_row_by_account( config::system_account_name, config::system_account_name, N(global), N(global) );

        // Total Stakes = whale1 + whale2 stakes = (40'000'000'0000 - 1,000) + (30'000'000'0000 - 1,000) = 69'999'999.8000
        BOOST_TEST(get_global_state()["total_activated_stake"].as<int64_t>() == 699999998000);

        // No producers will be set, since the total activated stake is less than 150,000,000
        produce_blocks_for_n_rounds(2); // 2 rounds since new producer schedule is set when the first block of next round is irreversible
        auto active_schedule = control->head_block_state()->active_schedule;
        BOOST_TEST(active_schedule.producers.size() == 1u);
        BOOST_TEST(active_schedule.producers.front().producer_name == name("rem"));

        // This will increase the total vote stake by (1'000'000'000'000 - 1,000)
        votepro( N(b1), {N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
                         N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
                         N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)} );
        BOOST_TEST(get_global_state()["total_activated_stake"].as<int64_t>() == 1699999997000); // 169'999'999.7000


        // Since the total vote stake is more than 150,000,000, the new producer set will be set
        produce_blocks_for_n_rounds(2); // 2 rounds since new producer schedule is set when the first block of next round is irreversible
        active_schedule = control->head_block_state()->active_schedule;
        BOOST_REQUIRE(active_schedule.producers.size() == 21);
        BOOST_TEST(active_schedule.producers.at(0).producer_name == name("proda"));
        BOOST_TEST(active_schedule.producers.at(1).producer_name == name("prodb"));
        BOOST_TEST(active_schedule.producers.at(2).producer_name == name("prodc"));
        BOOST_TEST(active_schedule.producers.at(3).producer_name == name("prodd"));
        BOOST_TEST(active_schedule.producers.at(4).producer_name == name("prode"));
        BOOST_TEST(active_schedule.producers.at(5).producer_name == name("prodf"));
        BOOST_TEST(active_schedule.producers.at(6).producer_name == name("prodg"));
        BOOST_TEST(active_schedule.producers.at(7).producer_name == name("prodh"));
        BOOST_TEST(active_schedule.producers.at(8).producer_name == name("prodi"));
        BOOST_TEST(active_schedule.producers.at(9).producer_name == name("prodj"));
        BOOST_TEST(active_schedule.producers.at(10).producer_name == name("prodk"));
        BOOST_TEST(active_schedule.producers.at(11).producer_name == name("prodl"));
        BOOST_TEST(active_schedule.producers.at(12).producer_name == name("prodm"));
        BOOST_TEST(active_schedule.producers.at(13).producer_name == name("prodn"));
        BOOST_TEST(active_schedule.producers.at(14).producer_name == name("prodo"));
        BOOST_TEST(active_schedule.producers.at(15).producer_name == name("prodp"));
        BOOST_TEST(active_schedule.producers.at(16).producer_name == name("prodq"));
        BOOST_TEST(active_schedule.producers.at(17).producer_name == name("prodr"));
        BOOST_TEST(active_schedule.producers.at(18).producer_name == name("prods"));
        BOOST_TEST(active_schedule.producers.at(19).producer_name == name("prodt"));
        BOOST_TEST(active_schedule.producers.at(20).producer_name == name("produ"));
    } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( rem_vote_weight_test, voting_tester ) {
    try {
        // Register producers
        const auto producer_candidates = {
                N(proda), N(prodb), N(prodc), N(prodd), N(prode), N(prodf), N(prodg),
                N(prodh), N(prodi), N(prodj), N(prodk), N(prodl), N(prodm), N(prodn),
                N(prodo), N(prodp), N(prodq), N(prodr), N(prods), N(prodt), N(produ)
        };
        for( const auto& producer : producer_candidates ) {
            register_producer(producer);
        }

        // Register whales as producers
        const auto whales_as_producers = { N(b1), N(whale1), N(whale2), N(whale2) };
        for( const auto& producer : whales_as_producers ) {
            register_producer(producer);
        }

        // Day 0
        {
            const auto voter = get_voter_info( name("whale1") );
            BOOST_TEST_REQUIRE( 0.0 == voter["last_vote_weight"].as_double() );

            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 0.0 == prod["total_votes"].as_double() );
        }

        {
            votepro( N(whale1), { N(proda) } );
            // vote gains full power at:     1593388805500000
            // voteproducer was done at:     1577836844500000
            // 180 days in microseconds is:  15552000000000

            // eos weight:      1.091357477572318e+06;
            // weeks to mature: 25;
            // rem weight:      0.027;
            // staked:          399999999000;
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 12126194164932502 == prod["total_votes"].as_double() );
        }

        // Day 30
        {
            produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::seconds(30 * 24 * 3600)); // +30 days
            votepro( N(whale1), { N(proda) } );

            // eos weight:      1.151126844657861e+06;
            // weeks to mature: 21;
            // rem weight:      0.183;
            // staked:          399999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 84415968397203200 == prod["total_votes"].as_double() );
        }

        // Day 30+
        // `days to mature` and `rem weight` should be the same within 1 day
        {
            produce_blocks( 500 );
            votepro( N(whale1), { N(proda) } );

            // eos weight:      1.151126844657861e+06;
            // weeks to mature: 21;
            // rem weight:      0.183;
            // staked:          399999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 84415968397203200 == prod["total_votes"].as_double() );
        }

        // Day 180
        {
            produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::seconds(150 * 24 * 3600)); // +150 days
            votepro( N(whale1), { N(proda) } );

            // eos weight:      1.543412546180063e+06;
            // weeks to mature: 0;
            // rem weight:      1.000000;
            // staked:          399999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 6.1736501692861286e+17 == prod["total_votes"].as_double() );
        }

        // Day 180 (0)
        // re-staking vote power 100%
        // staked 40KK
        // re-staked 20KK
        {
            const auto r = delegate_bandwidth(N(rem.stake), N(whale1), asset(20'000'000'0000LL));
            BOOST_REQUIRE( !r->except_ptr );

            votepro( N(whale1), { N(proda) } );

            // adjusted:   now + 0 Days * 40 / 60 + 180 Days * 20 / 60 => 60 Days
            // weeks to mature: 8;
            // eos weight:      1.543412546180063e+06;
            // rem weight:      0.688;
            // staked:          599999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 6.3794385135785318e+17 == prod["total_votes"].as_double() );
        }

        // Day 210 (30)
        // re-staking vote power 84%
        // staked 60KK
        // re-staked 20KK
        {
            produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::seconds(30 * 24 * 3600)); // +30 days

            // `last_vote_weight` and `last_reassertion_time` should not change after `delegate_bandwidth`
            // explanation bug https://www.reddit.com/r/eos/comments/b74xpy/bps_are_exploiting_a_protocol_bug_to_manipulate/?utm_source=amp&utm_medium=&utm_content=post_body
            const auto whale1_info_before = get_voter_info( name("whale1") );
            const auto r = delegate_bandwidth(N(rem.stake), N(whale1), asset(20'000'000'0000LL));
            const auto whale1_info_after = get_voter_info( name("whale1") );

            BOOST_REQUIRE( !r->except_ptr );
            BOOST_TEST_REQUIRE( whale1_info_before["last_vote_weight"] == whale1_info_after["last_vote_weight"] );
            BOOST_TEST_REQUIRE( whale1_info_before["last_reassertion_time"] == whale1_info_after["last_reassertion_time"] );

            votepro( N(whale1), { N(proda) } );

            // adjusted:   now + 30 Days * 60 / 80 + 180 Days * 20 / 80 => 67.5 Days
            // weeks to mature: 4;
            // eos weight:      1.627939195726894e+06;
            // rem weight:      0.844444;
            // staked:          799999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 8.4652838071982426e+17 == prod["total_votes"].as_double() );
        }

        // 8 Weeks Later
        {
            produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::days( 7 * 8 )); // +8 weeks
            votepro( N(whale1), { N(proda) } );

            // weeks to mature: 1;
            // eos weight:      1.811133596417372e+06;
            // rem weight:      0.961;
            // staked:          799999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 1.3925604968379901e+18 == prod["total_votes"].as_double() );

        }

        // 1 Week Later
        {
            produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(fc::days( 7 )); // +1 week
            votepro( N(whale1), { N(proda) } );

            // weeks to mature: 0;
            // eos weight:      1.860066895765736e+06;
            // rem weight:      1.000;
            // staked:          799999999000
            const auto prod = get_producer_info( name("proda") );
            BOOST_TEST_REQUIRE( 1.4880535147525217e+18 == prod["total_votes"].as_double() );

        }

        // Test removing votes
        {
           const auto voter_before = get_voter_info( name("whale1") );
           BOOST_TEST_REQUIRE( 0.0 < voter_before["last_vote_weight"].as_double() );
           votepro( N(whale1), {} );

           // last_vote_weight should be 0
           const auto voter_after = get_voter_info( name("whale1") );
           BOOST_TEST_REQUIRE( 0.0 == voter_after["last_vote_weight"].as_double() );
        }
    } FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( stake_lock_period_test, voting_tester ) {
   try {
      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time = fc::microseconds(1577836806000000);
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
      }

      // Re-delegating after 90 Days
      // GMT: Tuesday, March 31, 2020
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(90) );
         delegate_bandwidth( N(rem.stake), N(proda), asset( 1'000'000'0000LL ) );

         // Staked:      500'000'0000
         // Re-staked: 1'000'000'0000
         // Total:     1'500'000'0000

         // Days to mature: 90
         // New period: 1/3 * 90 + 2/3 * 180 = 150
         // GMT: Saturday, August 29, 2020
         const auto expected_lock_period = fc::microseconds( 1598577990345000 );

         const auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
      }


      // Re-delegating after 90 Days
      // New lock period is 90 Days
      // GMT: Monday, June 29, 2020
      {
         set_lock_period( 90 );
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(90) );
         delegate_bandwidth( N(rem.stake), N(proda), asset( 1'000'000'0000LL ) );

         // Staked:    1'500'000'0000
         // Re-staked: 1'000'000'0000
         // Total:     2'500'000'0000

         // Days to mature: 60
         // New period: 3/5 * 60 + 2/5 * 90 = 72
         // GMT: Wednesday, September 9, 2020
         const auto expected_lock_period = fc::microseconds(1599618933049000);

         const auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
      }


      // 72 Days later
      // GMT: Wednesday, September 9, 2020
      // Producer should be allowed to unregister, so stake is locked for another 6 months
      {
         // TODO should be removed when stake unlock logic is applied to lock instead of producer status
         {
            const auto producers = { N(b1), N(proda), N(whale1), N(whale2), N(whale3) };
            for( const auto& producer : producers ) {
               register_producer( producer );
               votepro( producer, { producer } );
            }
         }

         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days( 72 ) );
         BOOST_REQUIRE( unregister_producer( N(proda) ) );

         // GMT: Tuesday, March 9, 2021
         const auto expected_lock_period = fc::microseconds( 1599618933049000 );

         const auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
      }
   }
   FC_LOG_AND_RETHROW()
}

BOOST_FIXTURE_TEST_CASE( undelegate_locked_stake_test, voting_tester ) {
   try {
      // we need this to activate 15% of tokens
      const auto producers = { N(b1), N(whale1), N(whale2), N(whale3), N(proda) };
      for( const auto& producer : producers ) {
         register_producer(producer);
         votepro( producer, { producer } );
      }

      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time         = fc::microseconds(1577836806000000);
      const auto initial_locked_stake = 499'999'9000LL;
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
         BOOST_TEST( initial_locked_stake == voter["locked_stake"].as_int64() );
      }

      // We are not allowed to undelegate during stake lock period
      {
         BOOST_REQUIRE_EXCEPTION( undelegate_bandwidth( N(proda), N(proda), core_from_string("1.0000") ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: cannot undelegate during stake lock period") );
      }

      // +180 Days
      // GMT: Monday, June 29, 2020
      const auto undelegated_funds = 100'000'0000LL;
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(180) );

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );
         BOOST_TEST( asset{0} == get_balance(N(proda)) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( (initial_locked_stake - undelegated_funds) == voter["staked"].as_int64() );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         BOOST_REQUIRE_EXCEPTION( refund( N(proda) ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: already claimed refunds within past day") );
      }

      // fixes `no balance object found`
      // we need this because balances added before rem.system is deployed
      // in usual scenario tokens are transfered to rem.stake via `delegatebw` action
      transfer( config::system_account_name, N(rem.stake), asset{ 1'000'000'0000LL } );

      // Day 10
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(10) );

         const int64_t expected_locked_stake = undelegated_funds - 10 * 5555555.5;

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         
         refund( N(proda) );
         BOOST_TEST( asset{undelegated_funds - expected_locked_stake} == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ expected_locked_stake } == proda_refund["resource_amount"].as<asset>() );
      }

      // Day 60
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(50) );

         refund( N(proda) );
         BOOST_TEST( asset{ 33'497'6988LL } == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ 66'502'3012LL } == proda_refund["resource_amount"].as<asset>() );
      }

      // Day 180
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(120) );

         refund( N(proda) );
         BOOST_TEST( asset{ 100'000'0000LL } == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( proda_refund.is_null() );
      }
   } FC_LOG_AND_RETHROW()
}


BOOST_FIXTURE_TEST_CASE( full_refund_to_stake_test, voting_tester ) {
   try {
      // we need this to activate 15% of tokens
      const auto producers = { N(b1), N(whale1), N(whale2), N(whale3), N(proda) };
      for( const auto& producer : producers ) {
         register_producer(producer);
         votepro( producer, { producer } );
      }

      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time         = fc::microseconds(1577836806000000);
      const auto initial_locked_stake = 499'999'9000LL;
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
         BOOST_TEST( initial_locked_stake == voter["locked_stake"].as_int64() );
      }

      // We are not allowed to undelegate during stake lock period
      {
         BOOST_REQUIRE_EXCEPTION( undelegate_bandwidth( N(proda), N(proda), core_from_string("1.0000") ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: cannot undelegate during stake lock period") );
      }

      // +180 Days
      // GMT: Monday, June 29, 2020
      const auto undelegated_funds = 100'000'0000LL;
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(180) );

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );
         BOOST_TEST( asset{0} == get_balance(N(proda)) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( (initial_locked_stake - undelegated_funds) == voter["staked"].as_int64() );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         BOOST_REQUIRE_EXCEPTION( refund( N(proda) ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: already claimed refunds within past day") );
      }

      // full refund to stake should be available right away
      {
         const auto lock_time_before_refund = microseconds_since_epoch_of_iso_string( get_voter_info( N(proda) )["stake_lock_time"] ).count();
         refund_to_stake( N(proda) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( initial_locked_stake == voter["staked"].as_int64() );
         BOOST_TEST( asset{0} == get_balance( N(proda)) );

         const auto lock_time_after_refund = microseconds_since_epoch_of_iso_string( get_voter_info( N(proda) )["stake_lock_time"] ).count();
         BOOST_TEST( lock_time_before_refund == lock_time_after_refund );
      }
   } FC_LOG_AND_RETHROW()
}


BOOST_FIXTURE_TEST_CASE( partial_refund_to_stake_test, voting_tester ) {
   try {
      // we need this to activate 15% of tokens
      const auto producers = { N(b1), N(whale1), N(whale2), N(whale3), N(proda) };
      for( const auto& producer : producers ) {
         register_producer(producer);
         votepro( producer, { producer } );
      }

      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time         = fc::microseconds(1577836806000000);
      const auto initial_locked_stake = 499'999'9000LL;
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
         BOOST_TEST( initial_locked_stake == voter["locked_stake"].as_int64() );
      }

      // We are not allowed to undelegate during stake lock period
      {
         BOOST_REQUIRE_EXCEPTION( undelegate_bandwidth( N(proda), N(proda), core_from_string("1.0000") ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: cannot undelegate during stake lock period") );
      }

      // +180 Days
      // GMT: Monday, June 29, 2020
      const auto undelegated_funds = 100'000'0000LL;
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(180) );

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );
         BOOST_TEST( asset{0} == get_balance(N(proda)) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( (initial_locked_stake - undelegated_funds) == voter["staked"].as_int64() );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         BOOST_REQUIRE_EXCEPTION( refund( N(proda) ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: already claimed refunds within past day") );
      }

      // fixes `no balance object found`
      // we need this because balances added before rem.system is deployed
      // in usual scenario tokens are transfered to rem.stake via `delegatebw` action
      transfer( config::system_account_name, N(rem.stake), asset{ 1'000'000'0000LL } );

      // Day 60 after lock period
      // GMT: Friday, August 28, 2020
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(60) );

         const auto lock_time_before_refund = microseconds_since_epoch_of_iso_string( get_voter_info( N(proda) )["stake_lock_time"] ).count();
         refund_to_stake( N(proda) );

         const auto voter = get_voter_info( N(proda) );
         // 399'999'9000 + 120 * 100'000'0000 / 180
         BOOST_TEST( 466'666'5666LL == voter["staked"].as_int64() );
         BOOST_TEST( asset{0} == get_balance( N(proda)) );

         const auto lock_time_after_refund = microseconds_since_epoch_of_iso_string( get_voter_info( N(proda) )["stake_lock_time"] ).count();
         BOOST_TEST( lock_time_before_refund == lock_time_after_refund );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ 333'333'334LL } == proda_refund["resource_amount"].as<asset>() );

         const auto expected_unlock_time = 1598627106000000LL; // now (Friday, August 28, 2020)
         const auto unlock_time = microseconds_since_epoch_of_iso_string( proda_refund["unlock_time"] ).count();
         BOOST_TEST( expected_unlock_time == unlock_time );

         refund( N(proda) );
         BOOST_TEST( 466'666'5666LL == voter["staked"].as_int64() );
         BOOST_TEST( asset{333'333'334LL} == get_balance( N(proda) ) );
      }
   } FC_LOG_AND_RETHROW()
}


BOOST_FIXTURE_TEST_CASE( re_undelegate_locked_stake_test, voting_tester ) {
   try {
      // we need this to activate 15% of tokens
      const auto producers = { N(b1), N(whale1), N(whale2), N(whale3), N(proda) };
      for( const auto& producer : producers ) {
         register_producer(producer);
         votepro( producer, { producer } );
      }

      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time         = fc::microseconds(1577836806000000);
      const auto initial_locked_stake = 499'999'9000LL;
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
         BOOST_TEST( initial_locked_stake == voter["locked_stake"].as_int64() );
      }

      // We are not allowed to undelegate during stake lock period
      {
         BOOST_REQUIRE_EXCEPTION( undelegate_bandwidth( N(proda), N(proda), core_from_string("1.0000") ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: cannot undelegate during stake lock period") );
      }

      // +180 Days
      // GMT: Monday, June 29, 2020
      const auto undelegated_funds = 100'000'0000LL;
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(180) );

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );
         BOOST_TEST( asset{0} == get_balance(N(proda)) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( (initial_locked_stake - undelegated_funds) == voter["staked"].as_int64() );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         const auto request_time = microseconds_since_epoch_of_iso_string( proda_refund["request_time"] ).count();
         const auto unlock_time = microseconds_since_epoch_of_iso_string( proda_refund["unlock_time"] ).count();
         const auto expected_unlock_time = request_time + fc::days(180).count();
         BOOST_TEST( unlock_time == expected_unlock_time );
      }

      // fixes `no balance object found`
      // we need this because balances added before rem.system is deployed
      // in usual scenario tokens are transfered to rem.stake via `delegatebw` action
      transfer( config::system_account_name, N(rem.stake), asset{ 1'000'000'0000LL } );

      // Day 60
      // GMT: Friday, August 28, 2020
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(60) );

         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ 2 * undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         const auto unlock_time = microseconds_since_epoch_of_iso_string( proda_refund["unlock_time"] ).count();
         // current time + 0.5 * (180 - 60 days) + 0.5 * 180
         const auto expected_unlock_time = 1611569960500000LL; // GMT: Monday, January 25, 2021
         BOOST_TEST( unlock_time == expected_unlock_time );

         // undelegating resets last claim time to now so unlocked tokens are locked again
         const auto last_claim_time = microseconds_since_epoch_of_iso_string( proda_refund["last_claim_time"] ).count();
         const auto expected_last_claim_time = 1598627106000000; // GMT: Friday, August 28, 2020
         BOOST_TEST( last_claim_time == expected_last_claim_time );
      }
   } FC_LOG_AND_RETHROW()
}


BOOST_FIXTURE_TEST_CASE( undelegate_small_amount_test, voting_tester ) {
   try {
      // we need this to activate 15% of tokens
      const auto producers = { N(b1), N(whale1), N(whale2), N(whale3), N(proda) };
      for( const auto& producer : producers ) {
         register_producer(producer);
         votepro( producer, { producer } );
      }

      // Initial stake delegating
      // GMT: Wednesday, January 1, 2020
      const auto initial_time         = fc::microseconds(1577836806000000);
      const auto initial_locked_stake = 499'999'9000LL;
      {
         // Initital stake lock is due to
         // GMT: Monday, June 29, 2020
         const auto expected_lock_period = initial_time + fc::days(180);

         auto voter = get_voter_info( name("proda") );
         BOOST_CHECK( expected_lock_period == microseconds_since_epoch_of_iso_string( voter["stake_lock_time"] ) );
         BOOST_TEST( initial_locked_stake == voter["locked_stake"].as_int64() );
      }

      // We are not allowed to undelegate during stake lock period
      {
         BOOST_REQUIRE_EXCEPTION( undelegate_bandwidth( N(proda), N(proda), core_from_string("1.0000") ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: cannot undelegate during stake lock period") );
      }

      // +180 Days
      // GMT: Monday, June 29, 2020
      const auto undelegated_funds = 100LL;
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(180) );

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         undelegate_bandwidth( N(proda), N(proda), asset{ undelegated_funds } );
         BOOST_TEST( asset{0} == get_balance(N(proda)) );

         const auto voter = get_voter_info( N(proda) );
         BOOST_TEST( (initial_locked_stake - undelegated_funds) == voter["staked"].as_int64() );

         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ undelegated_funds } == proda_refund["resource_amount"].as<asset>() );

         BOOST_REQUIRE_EXCEPTION( refund( N(proda) ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: already claimed refunds within past day") );
      }

      // fixes `no balance object found`
      // we need this because balances added before rem.system is deployed
      // in usual scenario tokens are transfered to rem.stake via `delegatebw` action
      transfer( config::system_account_name, N(rem.stake), asset{ 1'000'000'0000LL } );

      // Day 1
      // 100 * 1 / 180 = 0.5(5) is less than minimal precision of tokens
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(1) );

         BOOST_REQUIRE_EXCEPTION( refund( N(proda) ), eosio_assert_message_exception, fc_exception_message_is("assertion failure with message: insufficient unlocked amount") );
      }

      // Day 10
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(9) );

         const int64_t expected_locked_stake = undelegated_funds - 10 * 0.5555;

         BOOST_TEST( asset{0} == get_balance(N(proda)) );
         
         refund( N(proda) );
         BOOST_TEST( asset{undelegated_funds - expected_locked_stake} == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ expected_locked_stake } == proda_refund["resource_amount"].as<asset>() );
      }

      // Day 170
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(160) );

         refund( N(proda) );
         BOOST_TEST( asset{ 95LL } == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ 5LL } == proda_refund["resource_amount"].as<asset>() );
      }

      // Day 175
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(5) );

         refund( N(proda) );
         BOOST_TEST( asset{ 98LL } == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( asset{ 2LL } == proda_refund["resource_amount"].as<asset>() );
      }

      // Day 180
      {
         produce_min_num_of_blocks_to_spend_time_wo_inactive_prod( fc::days(5) );

         refund( N(proda) );
         BOOST_TEST( asset{ 100LL } == get_balance(N(proda)) );
         
         const auto proda_refund = get_refund_request( N(proda) );
         BOOST_TEST( proda_refund.is_null() );
      }
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_SUITE_END()