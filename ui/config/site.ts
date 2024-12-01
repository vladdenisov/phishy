export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: "Phishy",
  description: "Сервис для сканирования и анализа веб-ресурсов",
  navItems: [
    {
      label: "Главная",
      href: "/",
    },
    {
      label: "Вебсайт",
      href: "/html",
    },
    {
      label: "URL",
      href: "/url",
    },
    {
      label: "Письма",
      href: "/email",
    },
  ],
  navMenuItems: [
    {
      label: "Главная",
      href: "/",
    },
    {
      label: "Вебсайт",
      href: "/html",
    },
    {
      label: "URL",
      href: "/url",
    },
    {
      label: "Письма",
      href: "/email",
    },
  ],
};
