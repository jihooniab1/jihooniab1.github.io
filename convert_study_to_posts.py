#!/usr/bin/env python3
"""
Study 폴더의 마크다운 파일들을 Jekyll 블로그 포스트로 변환하는 스크립트
"""
import os
import re
import shutil
from pathlib import Path
from datetime import datetime

# 설정
STUDY_DIR = Path("/home/user/Private/Study")
BLOG_DIR = Path("/home/user/Private/jihooniab1.github.io")
POSTS_DIR = BLOG_DIR / "_posts"
ASSETS_IMG_DIR = BLOG_DIR / "assets" / "img" / "posts"

def extract_title_from_md(content):
    """마크다운 파일에서 첫 번째 # 제목 추출"""
    lines = content.split('\n')
    for line in lines:
        if line.strip().startswith('# '):
            return line.strip()[2:].strip()
    return None

def get_category_from_path(md_path):
    """파일 경로에서 카테고리 추출"""
    relative_path = md_path.relative_to(STUDY_DIR)
    parts = list(relative_path.parts[:-1])  # 파일명 제외

    # 빈 카테고리면 기본값
    if not parts:
        return ["Study"]

    return parts

def slugify(text):
    """파일명으로 사용 가능한 형태로 변환"""
    # 한글, 영문, 숫자만 남기고 나머지는 하이픈으로
    text = text.lower()
    text = re.sub(r'[^\w\s가-힣-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = text.strip('-')
    return text[:100]  # 최대 100자

def convert_image_paths(content, md_path, category_slug):
    """이미지 경로를 Jekyll 형식으로 변환"""
    # 현재 파일의 디렉토리
    md_dir = md_path.parent

    # 이미지 패턴 찾기: ![alt](경로)
    def replace_image(match):
        alt_text = match.group(1)
        img_path = match.group(2)

        # 절대 경로나 URL은 그대로
        if img_path.startswith(('http://', 'https://', '/')):
            return match.group(0)

        # 상대 경로 처리
        full_img_path = (md_dir / img_path).resolve()

        if full_img_path.exists():
            # 이미지 파일명
            img_filename = full_img_path.name
            # Jekyll assets 경로
            new_path = f"/assets/img/posts/{category_slug}/{img_filename}"
            return f"![{alt_text}]({new_path})"
        else:
            # 이미지 파일이 없으면 원본 유지
            return match.group(0)

    pattern = r'!\[([^\]]*)\]\(([^)]+\.(png|jpg|jpeg|gif|svg|PNG|JPG|JPEG|GIF|SVG))\)'
    converted_content = re.sub(pattern, replace_image, content)

    return converted_content

def copy_images(md_path, category_slug):
    """마크다운 파일에서 참조하는 이미지들을 assets 폴더로 복사"""
    content = md_path.read_text(encoding='utf-8')
    md_dir = md_path.parent

    # 이미지 경로 찾기
    pattern = r'!\[([^\]]*)\]\(([^)]+\.(png|jpg|jpeg|gif|svg|PNG|JPG|JPEG|GIF|SVG))\)'
    matches = re.findall(pattern, content)

    copied_images = []
    for alt_text, img_path, ext in matches:
        # 절대 경로나 URL은 스킵
        if img_path.startswith(('http://', 'https://', '/')):
            continue

        # 상대 경로 처리
        full_img_path = (md_dir / img_path).resolve()

        if full_img_path.exists():
            # 대상 디렉토리 생성
            dest_dir = ASSETS_IMG_DIR / category_slug
            dest_dir.mkdir(parents=True, exist_ok=True)

            # 이미지 복사
            dest_path = dest_dir / full_img_path.name
            shutil.copy2(full_img_path, dest_path)
            copied_images.append((full_img_path, dest_path))

    return copied_images

def create_front_matter(title, categories, tags=None):
    """Front Matter 생성"""
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S +0900")

    # 카테고리를 대괄호로 감싸기
    categories_str = "[" + ", ".join(categories) + "]"

    front_matter = f"""---
title: "{title}"
date: {date}
categories: {categories_str}
tags: []
---

"""
    return front_matter

def convert_file(md_path, preview=True):
    """단일 마크다운 파일 변환"""
    try:
        # 파일 읽기
        content = md_path.read_text(encoding='utf-8')

        # 제목 추출
        title = extract_title_from_md(content)
        if not title:
            title = md_path.stem

        # 카테고리 추출
        categories = get_category_from_path(md_path)
        category_slug = slugify('-'.join(categories))

        # 이미지 경로 변환
        converted_content = convert_image_paths(content, md_path, category_slug)

        # Front Matter 추가
        front_matter = create_front_matter(title, categories)
        final_content = front_matter + converted_content

        # 파일명 생성 (날짜-제목.md)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = f"{date_str}-{slugify(title)}.md"
        dest_path = POSTS_DIR / filename

        result = {
            'source': str(md_path),
            'dest': str(dest_path),
            'title': title,
            'categories': categories,
            'category_slug': category_slug,
            'success': True,
            'error': None
        }

        if not preview:
            # 실제 변환 실행
            POSTS_DIR.mkdir(parents=True, exist_ok=True)
            dest_path.write_text(final_content, encoding='utf-8')

            # 이미지 복사
            copied_images = copy_images(md_path, category_slug)
            result['copied_images'] = copied_images

        return result

    except Exception as e:
        return {
            'source': str(md_path),
            'success': False,
            'error': str(e)
        }

def find_markdown_files():
    """Study 폴더에서 모든 마크다운 파일 찾기"""
    md_files = []
    for md_path in STUDY_DIR.rglob("*.md"):
        # README.md는 제외 (너무 많음)
        if md_path.name == "README.md":
            # 하지만 내용이 많으면 포함
            content = md_path.read_text(encoding='utf-8')
            if len(content) < 100:  # 100자 미만이면 제외
                continue
        md_files.append(md_path)

    return sorted(md_files)

def preview_conversion():
    """변환 미리보기"""
    print("=" * 80)
    print("📋 Study 폴더 → Jekyll 블로그 변환 미리보기")
    print("=" * 80)
    print()

    md_files = find_markdown_files()
    print(f"✅ 발견한 마크다운 파일: {len(md_files)}개\n")

    results = []
    for i, md_path in enumerate(md_files, 1):
        result = convert_file(md_path, preview=True)
        results.append(result)

        if result['success']:
            print(f"{i}. ✓ {result['title'][:60]}")
            print(f"   📂 카테고리: {' > '.join(result['categories'])}")
            print(f"   📄 {Path(result['source']).relative_to(STUDY_DIR)}")
            print(f"   → {Path(result['dest']).name}")
        else:
            print(f"{i}. ✗ {result['source']}")
            print(f"   ❌ 오류: {result['error']}")
        print()

    print("=" * 80)
    successful = sum(1 for r in results if r['success'])
    print(f"✅ 변환 가능: {successful}/{len(results)}개")
    print("=" * 80)

    return results

def execute_conversion():
    """실제 변환 실행"""
    print("=" * 80)
    print("🚀 변환 시작...")
    print("=" * 80)
    print()

    md_files = find_markdown_files()

    results = []
    for i, md_path in enumerate(md_files, 1):
        result = convert_file(md_path, preview=False)
        results.append(result)

        if result['success']:
            print(f"{i}/{len(md_files)} ✓ {result['title'][:60]}")
            if 'copied_images' in result:
                print(f"   🖼️  이미지 {len(result['copied_images'])}개 복사됨")
        else:
            print(f"{i}/{len(md_files)} ✗ 오류: {result['error']}")

    print()
    print("=" * 80)
    successful = sum(1 for r in results if r['success'])
    print(f"✅ 변환 완료: {successful}/{len(results)}개")
    print(f"📁 포스트 위치: {POSTS_DIR}")
    print(f"🖼️  이미지 위치: {ASSETS_IMG_DIR}")
    print("=" * 80)

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        execute_conversion()
    else:
        preview_conversion()
        print()
        print("💡 실제로 변환하려면: python convert_study_to_posts.py --execute")
