#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <string>

namespace eosio {
    using std::string;

    class [[eosio::contract("truegrail_eos")]] truegrail_eos: public contract {
        public:
            truegrail_eos(name code, name receiver, datastream<const char*> ds): contract(code, receiver, ds) {
            };

            [[eosio::action]]
            void issue(uint64_t sneaker_id, string sneaker_info_hash) {
                require_auth(get_self());
                ownerships storage(get_self(), get_self().value);
                struct sneaker new_sneaker = {
                    .id = sneaker_id,
                    .info_hash = sneaker_info_hash,
                };
                storage.emplace(get_self(), [&](auto& row) {
                    row.sneaker = new_sneaker;
                });
            };

            [[eosio::action]]
            void transfer(uint64_t sneaker_id, uint64_t user_id, string user_info_hash) {
                require_auth(get_self());
                ownerships storage(get_self(), get_self().value);
                auto existing = storage.find(sneaker_id);
                check(existing != storage.end(), "sneaker does not exist!");
                storage.modify(existing, get_self(), [&] (auto& row) {
                    row.sneaker = existing -> sneaker;
                    struct user new_owner = {
                        .id = user_id,
                        .info_hash = user_info_hash,
                    };
                    row.owner = new_owner;
                });
            }


        private:
            struct user {
                uint64_t id;
                string info_hash;
            };

            struct sneaker {
                uint64_t id;
                string info_hash;
            };

            struct [[eosio::table]] history {
                checksum256 tx_hash;

                checksum256 primary_key()const {
                    return tx_hash;
                }
            };

            struct [[eosio::table]] ownership {
                sneaker sneaker;
                user owner;

                uint64_t primary_key()const {
                    return sneaker.id;
                };
            };

            typedef multi_index<"ownerships"_n, ownership> ownerships;
    };
}



