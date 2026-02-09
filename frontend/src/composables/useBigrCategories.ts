import { BIGR_CATEGORIES, BIGR_CATEGORY_LIST } from '@/types/bigr'
import type { BigrCategory, BigrCategoryInfo } from '@/types/bigr'

export function useBigrCategories() {
  function getCategoryInfo(category: BigrCategory): BigrCategoryInfo {
    return BIGR_CATEGORIES[category] ?? BIGR_CATEGORIES.unclassified
  }

  function getCategoryColor(category: BigrCategory): string {
    return getCategoryInfo(category).color
  }

  function getCategoryLabel(category: BigrCategory): string {
    return getCategoryInfo(category).label
  }

  function getCategoryLabelTr(category: BigrCategory): string {
    return getCategoryInfo(category).labelTr
  }

  const allCategories = BIGR_CATEGORY_LIST

  return {
    getCategoryInfo,
    getCategoryColor,
    getCategoryLabel,
    getCategoryLabelTr,
    allCategories,
  }
}
