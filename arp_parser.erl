-module(arp_parser).
-export([parse/1, print_arp/1, test/0]).

%% Запись для хранения разобранного ARP-пакета
-record(arp_packet, {
    htype,   %% Hardware type (2 байта)
    ptype,   %% Protocol type (2 байта)
    hsize,   %% Hardware size (1 байт)
    psize,   %% Protocol size (1 байт)
    opcode,  %% Opcode (2 байта)
    sha,     %% Sender MAC (6 байт)
    spa,     %% Sender IP (4 байта)
    tha,     %% Target MAC (6 байт)
    tpa      %% Target IP (4 байта)
}).

%% ===================================================================
%% parse/1 – разбор ARP-пакета из бинарных данных
%% ===================================================================
-spec parse(binary()) -> {ok, #arp_packet{}} | {error, term()}.
parse(Binary) when is_binary(Binary) ->
    case byte_size(Binary) of
        28 ->
            %% Все многобайтовые числа хранятся в сетевом порядке
            <<HType:16/big, PType:16/big, HSize:8, PSize:8, Op:16/big, SHa:6/binary, SPa:4/binary, THa:6/binary, TPa:4/binary>> = Binary,
            %% Дополнительная проверка на соответствие типичным размерам
            case {HSize, PSize} of
                {6, 4} ->
                    {ok, #arp_packet{
                        htype = HType,
                        ptype = PType,
                        hsize = HSize,
                        psize = PSize,
                        opcode = Op,
                        sha   = SHa,
                        spa   = SPa,
                        tha   = THa,
                        tpa   = TPa
                    }};
                _ ->
                    {error, invalid_address_sizes}
            end;
        _ ->
            {error, invalid_length}
    end;
parse(_) ->
    {error, not_binary}.

%% ================================================================
%% print_arp/1 – вывод содержимого записи ARP-пакета
%% ================================================================
-spec print_arp(#arp_packet{}) -> ok.
print_arp(#arp_packet{
    htype = HType,
    ptype = PType,
    hsize = HSize,
    psize = PSize,
    opcode    = Op,
    sha   = SHa,
    spa   = SPa,
    tha   = THa,
    tpa   = TPa
}) ->
    io:format("ARP Packet:~n"),
    io:format("  Hardware type: ~4.16.0B~n", [HType]),
    io:format("  Protocol type: ~4.16.0B~n", [PType]),
    io:format("  Hardware size: ~B~n", [HSize]),
    io:format("  Protocol size: ~B~n", [PSize]),
    io:format("  Opcode: ~B~n", [Op]),
    io:format("  Sender MAC: ~s~n", [format_mac(SHa)]),
    io:format("  Sender IP: ~s~n", [format_ip(SPa)]),
    io:format("  Target MAC: ~s~n", [format_mac(THa)]),
    io:format("  Target IP: ~s~n", [format_ip(TPa)]).

%% -------------------------------------------------------------------
%% Вспомогательные функции форматирования MAC и IP
%% -------------------------------------------------------------------
format_mac(Mac) when byte_size(Mac) =:= 6 ->
    lists:flatten(
        io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B",
                      [binary:at(Mac, I) || I <- lists:seq(0,5)])
    ).

format_ip(Ip) when byte_size(Ip) =:= 4 ->
    lists:flatten(
        io_lib:format("~B.~B.~B.~B",
                      [binary:at(Ip, I) || I <- lists:seq(0,3)])
    ).

%% ===================================================================
%% Пример тестового запуска 
%% ===================================================================
test() ->
    TestPacket = <<
        16#00, 16#01, 16#08, 16#00, 16#06, 16#04, 16#00, 16#01,
        16#08, 16#00, 16#27, 16#12, 16#34, 16#56, 16#C0, 16#A8,
        16#01, 16#01, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
        16#C0, 16#A8, 16#01, 16#02
    >>,
    case parse(TestPacket) of
        {ok, Packet} ->
            print_arp(Packet);
        {error, Reason} ->
            io:format("Error: ~p~n", [Reason])
    end.


