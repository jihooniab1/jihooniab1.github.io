#!/usr/bin/env python3
"""
마크다운 내부 링크를 Jekyll 규칙에 맞게 수정
"""
import re
from pathlib import Path

POSTS_DIR = Path("/home/user/Private/jihooniab1.github.io/_posts")

def slugify_anchor(text):
    """Jekyll의 헤더 ID 생성 규칙 따르기"""
    # 소문자로 변환
    text = text.lower()
    # 공백을 하이픈으로
    text = text.replace(' ', '-')
    # 특수문자 제거 (하이픈, 한글, 영문, 숫자만 유지)
    text = re.sub(r'[^\w\-가-힣]', '', text)
    # 연속된 하이픈 제거
    text = re.sub(r'-+', '-', text)
    # 앞뒤 하이픈 제거
    text = text.strip('-')
    return text

def fix_markdown_links(content):
    """마크다운 파일의 내부 링크 수정"""

    def fix_link(match):
        text = match.group(1)
        anchor = match.group(2)

        # 외부 링크나 절대 경로는 건드리지 않음
        if not anchor.startswith('#'):
            return match.group(0)

        # # 제거하고 slug화
        anchor_text = anchor[1:]
        fixed_anchor = '#' + slugify_anchor(anchor_text)

        return f"[{text}]({fixed_anchor})"

    # [텍스트](#앵커) 패턴 찾기
    pattern = r'\[([^\]]+)\]\((#[^\)]+)\)'
    fixed_content = re.sub(pattern, fix_link, content)

    return fixed_content

def process_file(file_path):
    """단일 파일 처리"""
    try:
        content = file_path.read_text(encoding='utf-8')
        original = content

        fixed_content = fix_markdown_links(content)

        if fixed_content != original:
            file_path.write_text(fixed_content, encoding='utf-8')
            return True, file_path.name
        else:
            return False, file_path.name

    except Exception as e:
        return None, f"{file_path.name}: {e}"

def main():
    print("=" * 80)
    print("🔧 마크다운 내부 링크 수정 중...")
    print("=" * 80)
    print()

    md_files = list(POSTS_DIR.glob("*.md"))

    modified = []
    unchanged = []
    errors = []

    for md_file in md_files:
        result, name = process_file(md_file)

        if result is True:
            modified.append(name)
            print(f"✓ {name}")
        elif result is False:
            unchanged.append(name)
        else:
            errors.append(name)
            print(f"✗ {name}")

    print()
    print("=" * 80)
    print(f"✅ 수정됨: {len(modified)}개")
    print(f"⏭️  변경 없음: {len(unchanged)}개")
    if errors:
        print(f"❌ 오류: {len(errors)}개")
    print("=" * 80)

    if modified:
        print("\n수정된 파일:")
        for name in modified[:10]:
            print(f"  - {name}")
        if len(modified) > 10:
            print(f"  ... 외 {len(modified) - 10}개")

if __name__ == "__main__":
    main()
