import streamlit as st
from web3 import Web3
from hexbytes import HexBytes
from datetime import datetime
from collections import defaultdict
import time, random

st.set_page_config(page_title="On-Chain Token Analyzer", layout="wide")

st.title("On-Chain Token Analyzer")

with st.expander("Inputs"):
    with st.form("config_form"):
        col1, col2 = st.columns(2)
        with col1:
            rpc_primary = st.text_input(
                "Primary RPC",
                "https://mainnet.infura.io/v3/40932ea998e940ba943016f25e09246c",
            ).strip()
            rpc_fallback = st.text_input(
                "Fallback RPC",
                "https://rpc.ankr.com/eth",
            ).strip()
            token_addr = st.text_input(
                "Token Address (ERC-20)",
                "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",
            ).strip()
            lookback = st.number_input(
                "Block lookback (latest N blocks)", min_value=100, max_value=200000, value=2000, step=100
            )
            initial_span = st.number_input(
                "Initial log chunk size (blocks)", min_value=8, max_value=4096, value=64, step=8
            )
        with col2:
            non_circ_str = st.text_area(
                "Non-circulating addresses (one per line)",
                "0x0000000000000000000000000000000000000000\n0x000000000000000000000000000000000000dEaD",
                height=90,
            )
            boundary_str = st.text_area(
                "Boundary set (top holders, treasury, vaults… one per line)",
                "\n".join([
                    "0xF977814e90dA44bFA03b6295A0616a897441aceC",
                    "0x480234599362dC7a76cd99D09738A626F6d77e5F",
                    "0xA73d9021f67931563fDfe3E8f66261086319a1FC",
                    "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",
                    "0xD041AF244d15456AEdFaB358fa80D6e454f3bd27",
                    "0xf60c2Ea62EDBfE808163751DD0d8693DCb30019c",
                    "0x00f435FA1f4297D58644a5C96b75e26D45F9EA4B",
                    "0x424DBEd38cd0D83b13E2A150F86710Fb445680Cb",
                    "0x543E991e712bB51804D7Dc86924B6D4E9819542A",
                    "0x00897A5A07070dFb2817788802A2Bb70aa324ECC",
                ]),
                height=160,
            )
            sample_fee_txs = st.number_input(
                "Sample N txs for fee average (0 = all)", min_value=0, max_value=100000, value=0, step=100
            )
            rate_sleep = st.number_input("Rate-limit sleep (sec)", min_value=0.0, max_value=2.0, value=0.25, step=0.05)

        submitted = st.form_submit_button("Run analysis")

# ---------- helpers ----------
def connect_web3(rpc_url):
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        raise RuntimeError(f"RPC not connected: {rpc_url}")
    return w3

def to_checksum_list(raw):
    out = []
    for line in raw.splitlines():
        s = line.strip().strip(",")
        if not s:
            continue
        if not s.lower().startswith("0x"):
            continue
        try:
            out.append(Web3.to_checksum_address(s))
        except Exception:
            pass
    return out

def to_int_data(data_field):
    if isinstance(data_field, (bytes, bytearray, HexBytes)):
        return int.from_bytes(data_field, "big")
    s = data_field if isinstance(data_field, str) else data_field.hex()
    if not s.startswith("0x"):
        s = "0x" + s
    return int(s, 16)

def with_backoff(w3, fn, *args, rate_sleep=0.25):
    backoff = 1
    MAX_BACKOFF = 32
    while True:
        try:
            out = fn(*args)
            if rate_sleep:
                time.sleep(rate_sleep)
            return out
        except Exception as e:
            st.warning(f"RPC error: {e} | retry in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)

def get_logs_chunked(w3, address, topic0, start_block, end_block, initial_span=64, rate_sleep=0.25):
    """Yield logs over [start_block, end_block] with adaptive span; FORCE HEX BLOCKS and checksum address."""
    cur = start_block
    span = min(initial_span, end_block - start_block + 1)
    shown_debug = False
    while cur <= end_block:
        to_blk = min(cur + span - 1, end_block)

        # IMPORTANT: keep checksum-case; do NOT lowercase
        addr_str = Web3.to_checksum_address(address)

        params = {
            "fromBlock": hex(int(cur)),
            "toBlock":   hex(int(to_blk)),
            "address":   addr_str,
            "topics":    [
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            ],
        }

        try:
            if not shown_debug:
                st.caption(f"Debug getLogs params (first call): {params}")
                shown_debug = True
            logs = with_backoff(w3, lambda p: w3.eth.get_logs(p), params, rate_sleep=rate_sleep)
            for lg in logs:
                yield lg
            if len(logs) < 8000 and span < 4096:
                span = min(span * 2, 4096, end_block - to_blk) or span
            cur = to_blk + 1
        except Exception as e:
            st.warning(f"Chunk {cur}-{to_blk} failed: {e} → shrinking span")
            span = max(span // 2, 1)

# ---------- run ----------
if submitted:
    try:
        # connect
        try:
            w3 = connect_web3(rpc_primary)
            used_rpc = rpc_primary
        except Exception:
            w3 = connect_web3(rpc_fallback)
            used_rpc = rpc_fallback

        st.success(f"Connected to: {used_rpc} | chainId: {w3.eth.chain_id}")
        latest = w3.eth.block_number
        st.write(f"**Latest block:** {latest}")

        # validate token address early (keep checksum-case)
        if not token_addr.lower().startswith("0x") or len(token_addr) != 42:
            st.error("Token address must be a 42-char 0x… string.")
            st.stop()
        token = Web3.to_checksum_address(token_addr)

        # parse lists
        non_circ = to_checksum_list(non_circ_str)
        boundary = to_checksum_list(boundary_str)

        FROM_BLOCK = max(1, latest - int(lookback))
        TO_BLOCK   = latest

        # topic0 for ERC-20 Transfer
        topic0 = Web3.keccak(text="Transfer(address,address,uint256)").hex()
        if not topic0.startswith("0x"):
            topic0 = "0x" + topic0

        # ERC20
        ERC20_ABI = [
            {"name":"totalSupply","inputs":[],"outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
            {"name":"decimals","inputs":[],"outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"},
            {"name":"balanceOf","inputs":[{"name":"account","type":"address"}],
             "outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
        ]
        erc20 = w3.eth.contract(token, abi=ERC20_ABI)
        decimals = with_backoff(w3, lambda: erc20.functions.decimals().call(), rate_sleep=rate_sleep)
        SCALE = 10 ** decimals

        total = with_backoff(w3, lambda: erc20.functions.totalSupply().call(), rate_sleep=rate_sleep)
        noncirc_sum = 0
        for a in non_circ:
            try:
                noncirc_sum += with_backoff(w3, lambda addr=a: erc20.functions.balanceOf(addr).call(), rate_sleep=rate_sleep)
            except Exception:
                pass
        circ_supply = (total - noncirc_sum) / SCALE

        first_ts = with_backoff(w3, lambda: w3.eth.get_block(FROM_BLOCK).timestamp, rate_sleep=rate_sleep)
        last_ts  = with_backoff(w3, lambda: w3.eth.get_block(TO_BLOCK).timestamp,   rate_sleep=rate_sleep)

        # scan logs
        raw_sum = 0
        count = 0
        rows = []
        txhashes_for_fees = set()

        progress = st.progress(0.0, text="Scanning logs…")
        total_span = TO_BLOCK - FROM_BLOCK + 1
        scanned = 0

        for lg in get_logs_chunked(
            w3, token, topic0,
            start_block=FROM_BLOCK,
            end_block=TO_BLOCK,
            initial_span=int(initial_span),
            rate_sleep=rate_sleep
        ):
            val = to_int_data(lg["data"])
            raw_sum += val
            count += 1
            txh = lg["transactionHash"].hex()
            frm = Web3.to_checksum_address("0x" + lg["topics"][1].hex()[-40:])
            to  = Web3.to_checksum_address("0x" + lg["topics"][2].hex()[-40:])
            bn  = lg["blockNumber"]
            rows.append({"bn": bn, "txh": txh, "from": frm, "to": to, "value_raw": val})
            txhashes_for_fees.add(txh)
            scanned = max(scanned, bn - FROM_BLOCK + 1)
            progress.progress(min(scanned / total_span, 1.0))

        volume_tok = raw_sum / SCALE
        span_days = max((last_ts - first_ts) / 86400.0, 1e-9)
        velocity_win = (volume_tok / circ_supply) if circ_supply > 0 else float("nan")
        velocity_day = velocity_win / span_days

        st.subheader("Summary")
        c1, c2, c3 = st.columns(3)
        c1.metric("Transfers (logs)", f"{count:,}")
        c2.metric("Transfer volume (tokens)", f"{volume_tok:,.6f}")
        c3.metric("Circulating supply (now)", f"{circ_supply:,.6f}")

        c1, c2 = st.columns(2)
        c1.metric("Velocity (window)", f"{velocity_win:.6f}")
        c2.metric("Velocity per day", f"{velocity_day:.6f}")
        st.caption(f"Window: {FROM_BLOCK}-{TO_BLOCK}  [{datetime.utcfromtimestamp(first_ts)} .. {datetime.utcfromtimestamp(last_ts)} UTC]")

        # fees
        st.subheader("Fees (token Transfer txs in window)")
        fee_hashes = list(txhashes_for_fees)
        if sample_fee_txs and sample_fee_txs < len(fee_hashes):
            random.shuffle(fee_hashes)
            fee_hashes = fee_hashes[:sample_fee_txs]

        sum_fee_wei = 0
        sum_gas_used = 0
        fee_tx_count = 0
        for txh in fee_hashes:
            rcpt = with_backoff(w3, lambda h=txh: w3.eth.get_transaction_receipt(h), rate_sleep=rate_sleep)
            gas_used = rcpt.gasUsed
            egp = getattr(rcpt, "effectiveGasPrice", None)
            if egp is None:
                tx = with_backoff(w3, lambda h=txh: w3.eth.get_transaction(h), rate_sleep=rate_sleep)
                egp = tx.gasPrice
            sum_fee_wei += gas_used * egp
            sum_gas_used += gas_used
            fee_tx_count += 1

        avg_fee_eth = (sum_fee_wei / max(fee_tx_count, 1)) / 1e18
        avg_price_gwei = (sum_fee_wei / max(sum_gas_used, 1)) / 1e9
        colf1, colf2, colf3 = st.columns(3)
        colf1.metric("Txs counted", f"{fee_tx_count:,}")
        colf2.metric("Total fees (ETH)", f"{sum_fee_wei/1e18:,.6f}")
        colf3.metric("Avg fee/tx (ETH)", f"{avg_fee_eth:,.6f}")
        st.caption(f"Avg effective gas price (Gwei): {avg_price_gwei:,.2f}")

        # last-day biggest transfers
        st.subheader("Biggest transfers (last UTC day of window)")
        last_day = datetime.utcfromtimestamp(last_ts).date()
        block_ts_cache = {}
        def get_ts(bn):
            if bn not in block_ts_cache:
                block_ts_cache[bn] = with_backoff(w3, lambda b=bn: w3.eth.get_block(b).timestamp, rate_sleep=rate_sleep)
            return block_ts_cache[bn]
        day_rows = []
        for r in rows:
            if datetime.utcfromtimestamp(get_ts(r["bn"])).date() == last_day:
                day_rows.append({"amount": r["value_raw"]/SCALE, "from": r["from"], "to": r["to"], "tx": r["txh"]})
        day_rows.sort(key=lambda x: x["amount"], reverse=True)
        st.dataframe(day_rows[:10], use_container_width=True)

        # net issuance
        st.subheader("Global net issuance (window)")
        ZERO = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
        DEAD = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
        mint_raw = sum(r["value_raw"] for r in rows if r["from"] == ZERO)
        burn_raw = sum(r["value_raw"] for r in rows if r["to"] in (ZERO, DEAD))
        st.write(f"Mint volume: **{mint_raw/SCALE:,.6f}**")
        st.write(f"Burn volume: **{burn_raw/SCALE:,.6f}**")
        st.write(f"Net issuance (mint − burn): **{(mint_raw-burn_raw)/SCALE:,.6f}**")

        # net flow to contracts
        st.subheader("Net flow to contracts (EOA ↔ contracts)")
        code_cache = {}
        def is_contract(addr):
            if addr in (ZERO, DEAD): return False
            if addr in code_cache: return code_cache[addr]
            code = with_backoff(w3, lambda a=addr: w3.eth.get_code(a).hex(), rate_sleep=rate_sleep)
            code_cache[addr] = (code != "0x")
            return code_cache[addr]
        inflow_c = 0
        outflow_c = 0
        for r in rows:
            frm, to, val = r["from"], r["to"], r["value_raw"]
            if frm == ZERO or to in (ZERO, DEAD):
                continue
            if (not is_contract(frm)) and is_contract(to):
                inflow_c += val
            elif is_contract(frm) and (not is_contract(to)):
                outflow_c += val
        st.write(f"Inflows (EOA → contracts): **{inflow_c/SCALE:,.6f}**")
        st.write(f"Outflows (contracts → EOA): **{outflow_c/SCALE:,.6f}**")
        st.write(f"Net flow to contracts: **{(inflow_c-outflow_c)/SCALE:,.6f}**")

        # per-address net flow for boundary set
        st.subheader("Per-address net flow (Boundary Set) & Group total")
        if boundary:
            S = set(boundary)
            inflow_per = defaultdict(int)
            outflow_per = defaultdict(int)
            for r in rows:
                frm, to, val = r["from"], r["to"], r["value_raw"]
                if frm == ZERO or to in (ZERO, DEAD):
                    continue
                frm_in = frm in S
                to_in  = to in S
                if (not frm_in) and to_in:
                    inflow_per[to] += val
                elif frm_in and (not to_in):
                    outflow_per[frm] += val
            table = []
            group_total = 0.0
            for addr in boundary:
                inflow_tok = inflow_per[addr] / SCALE
                outflow_tok = outflow_per[addr] / SCALE
                net_tok = inflow_tok - outflow_tok
                group_total += net_tok
                table.append({"address": addr, "inflow": inflow_tok, "outflow": inflow_tok if False else outflow_tok, "net": net_tok})
            st.dataframe(table, use_container_width=True)
            st.metric("Group net flow (tokens)", f"{group_total:,.6f}")
        else:
            st.info("No addresses in Boundary Set. Add some to compute per-address and group net flow.")

    except Exception as e:
        st.error(f"Error: {e}")
