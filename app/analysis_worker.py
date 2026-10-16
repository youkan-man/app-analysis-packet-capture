"""One capture per OS process, controlled only through private parent pipes."""
from functools import lru_cache
import json
from pathlib import Path
import sys
from . import engine
from .filters import FilterError, parse_filter_groups
from .relationships import analyze


def serve(path: Path) -> None:
    # These caches belong to this process/file only; exit releases every decoded byte.
    engine.decoded_rows = lru_cache(maxsize=1)(engine.decoded_rows)
    detail = lru_cache(maxsize=16)(engine.packet_detail)
    relations = lru_cache(maxsize=8)(analyze)
    for line in sys.stdin:
        try:
            command = json.loads(line)
            operation, payload = command['operation'], command['payload']
            if operation == 'packets':
                result = engine.packet_list(path, payload.get('raw', ''),
                    parse_filter_groups(payload.get('view', '')), payload.get('context', 0))
            elif operation == 'detail':
                result = detail(path, payload['number'])
            elif operation == 'relations':
                result = relations(path, payload['number'])
            else:
                raise ValueError('Unknown operation')
            reply = {'ok': True, 'result': result}
        except (engine.DissectionError, FilterError) as exc:
            reply = {'ok': False, 'error': str(exc)}
        except Exception:
            reply = {'ok': False, 'error': '解析に失敗しました。ファイルを開き直してください'}
        sys.stdout.write(json.dumps(reply, ensure_ascii=False) + '\n')
        sys.stdout.flush()


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
