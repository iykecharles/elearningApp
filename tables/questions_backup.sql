PGDMP     "                    {        	   elearning    13beta3    13beta3     I           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            J           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            K           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            L           1262    107822 	   elearning    DATABASE     m   CREATE DATABASE elearning WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United States.1252';
    DROP DATABASE elearning;
                postgres    false            �            1259    116401 	   questions    TABLE     �  CREATE TABLE public.questions (
    questions_id bigint NOT NULL,
    topicsname character varying(255) NOT NULL,
    question_prompt text NOT NULL,
    option_a character varying(255) NOT NULL,
    option_b character varying(255) NOT NULL,
    option_c character varying(255) NOT NULL,
    option_d character varying(255) NOT NULL,
    correct_option integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.questions;
       public         heap    postgres    false            �            1259    116399    questions_questions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.questions_questions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE public.questions_questions_id_seq;
       public          postgres    false    211            M           0    0    questions_questions_id_seq    SEQUENCE OWNED BY     Y   ALTER SEQUENCE public.questions_questions_id_seq OWNED BY public.questions.questions_id;
          public          postgres    false    210            �
           2604    116404    questions questions_id    DEFAULT     �   ALTER TABLE ONLY public.questions ALTER COLUMN questions_id SET DEFAULT nextval('public.questions_questions_id_seq'::regclass);
 E   ALTER TABLE public.questions ALTER COLUMN questions_id DROP DEFAULT;
       public          postgres    false    210    211    211            F          0    116401 	   questions 
   TABLE DATA           �   COPY public.questions (questions_id, topicsname, question_prompt, option_a, option_b, option_c, option_d, correct_option, created_at) FROM stdin;
    public          postgres    false    211   �       N           0    0    questions_questions_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('public.questions_questions_id_seq', 24, true);
          public          postgres    false    210            �
           2606    116410    questions questions_pkey 
   CONSTRAINT     `   ALTER TABLE ONLY public.questions
    ADD CONSTRAINT questions_pkey PRIMARY KEY (questions_id);
 B   ALTER TABLE ONLY public.questions DROP CONSTRAINT questions_pkey;
       public            postgres    false    211            F   �  x�u�Mo�0����н�a��}	���t[vQl��"K�$7˿�nk�mنI�_�9��lm�#:��B���|��V{�;d�I�p�}k]+9n����yGf�L���tp7N��le�F
� 2�_f�eV3�[.�L�MË�H8��l���ߢ4��N�f��#ܢ�9�4=ܙ^I�7�-�6�iU�����k�f���N۹��� ��uv�������v����?������o������ق�k���8�d`D5�r ���u�&�[t,X�
Z­�A��v����^�Gy��Y�UmV�JV�	oHd�f�=t
M��y��]�<6gK�C�ervpr��3�������v�Ғ�&`���	�[�$W���G(^Ј�-˴�M�����]��Au�0$+�2(Oa4#J?;&�}4�G*�X��(i`6J�f�1O��>�*YOz�ޡ4tP��A��C�A��g���H��y	_,ڲJ�E]q��G���W��{0L��h�t'��m]>wf�C��`u� DIQ�E��Y^6u"�K�g�y�ծ�K��x&c�W$�������ޡe��X�_�eٖ��jYl[W.����Z��h���0��/����$���Yޒ�;��b�4Jg�����cz�����U�|��`�ޟm�(oZQ��"����&�Y%�`�VF�E^�%l����y[/eV��k�$�o8�j     