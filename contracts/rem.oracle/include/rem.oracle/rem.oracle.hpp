/**
 *  @copyright defined in eos/LICENSE.txt
 */

#pragma once

#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/eosio.hpp>

namespace remoracle {

   using eosio::asset;
   using eosio::block_timestamp;
   using eosio::check;
   using eosio::const_mem_fun;
   using eosio::current_time_point;
   using eosio::datastream;
   using eosio::indexed_by;
   using eosio::singleton;
   using eosio::seconds;
   using eosio::name;
   using eosio::time_point;
   using eosio::multi_index;
   using std::string;
   using std::vector;

   // A window in which producer can submit a new rate
   static constexpr uint32_t setprice_window_seconds = 3600;

   // Defines 'remprice' to be stored market price to the specified pairs
   struct [[eosio::table, eosio::contract("rem.oracle")]] remprice {
      name                    pair;
      double                  price = 0;
      vector<double>          price_points;
      block_timestamp         last_update;

      uint64_t primary_key()const { return pair.value; }

      // explicit serialization macro is not necessary, used here only to improve compilation time
      EOSLIB_SERIALIZE( remprice, (pair)(price)(price_points)(last_update))
   };

   typedef multi_index< "remprice"_n, remprice> remprice_idx;

   /**
    * @defgroup eosiooracle rem.oracle
    * @ingroup eosiocontracts
    *
    * rem.oracle contract
    *
    * @details rem.oracle contract defines the structures and actions that allow users and contracts set/get current
    * cryptocurrencies market price.
    * @{
    */

   class [[eosio::contract("rem.oracle")]] oracle : public eosio::contract {
   public:

      oracle(name receiver, name code,  datastream<const char*> ds);

      /**
       * Set the current market price of cryptocurrencies action.
       *
       * @details Set market price of supported cryptocurrencies.
       *
       * @param producer - the producer account to execute the setprice action for,
       * @param pairs_data - the rate of the pairs.
       */
      [[eosio::action]]
      void setprice(const name &producer, std::map<name, double> &pairs_data);

      /**
       * Add a new pair action.
       *
       * @details Add a new pair that will be supported, action permitted only for block producers.
       *
       * @param pair - the new pair name.
       */
      [[eosio::action]]
      void addpair(const name &pair);

   private:
      static constexpr name system_account = "rem"_n;

      struct [[eosio::table]] pricedata {
         name                    producer;
         std::map<name, double>  pairs_data;
         block_timestamp         last_update;

         uint64_t primary_key()const { return producer.value; }

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( pricedata, (producer)(pairs_data)(last_update))
      };

      struct [[eosio::table]] pairstable {
         std::set<name> pairs {};

         // explicit serialization macro is not necessary, used here only to improve compilation time
         EOSLIB_SERIALIZE( pairstable, (pairs))
      };

      typedef multi_index< "pricedata"_n, pricedata>  pricedata_idx;
      typedef singleton< "pairstable"_n,  pairstable> pairs_idx;

      pricedata_idx    pricedata_tbl;
      remprice_idx     remprice_tbl;
      pairs_idx        pairs_tbl;
      pairstable       pairstable_data;

      void check_pairs(const std::map<name, double> &pairs);
      void to_rewards(const asset &quantity, const name &payer);

      uint8_t get_majority_amount() const;
      std::map<name, vector<double>> get_relevant_prices() const;
      bool is_producer( const name& user ) const;

      double get_subset_median(vector<double> points) const;
      double get_median(const vector<double>& sorted_points) const;
   };
   /** @}*/ // end of @defgroup eosioauth rem.oracle
} /// namespace remoracle
