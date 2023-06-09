PGDMP                         {        	   elearning    13beta3    13beta3     K           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            L           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            M           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            N           1262    107822 	   elearning    DATABASE     m   CREATE DATABASE elearning WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United States.1252';
    DROP DATABASE elearning;
                postgres    false            �            1259    116413 	   responses    TABLE     	  CREATE TABLE public.responses (
    responses_id bigint NOT NULL,
    questions_id integer NOT NULL,
    answer integer NOT NULL,
    user_id integer NOT NULL,
    is_correct boolean NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.responses;
       public         heap    postgres    false            �            1259    116411    responses_responses_id_seq    SEQUENCE     �   CREATE SEQUENCE public.responses_responses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE public.responses_responses_id_seq;
       public          postgres    false    213            O           0    0    responses_responses_id_seq    SEQUENCE OWNED BY     Y   ALTER SEQUENCE public.responses_responses_id_seq OWNED BY public.responses.responses_id;
          public          postgres    false    212            �
           2604    116416    responses responses_id    DEFAULT     �   ALTER TABLE ONLY public.responses ALTER COLUMN responses_id SET DEFAULT nextval('public.responses_responses_id_seq'::regclass);
 E   ALTER TABLE public.responses ALTER COLUMN responses_id DROP DEFAULT;
       public          postgres    false    213    212    213            H          0    116413 	   responses 
   TABLE DATA           h   COPY public.responses (responses_id, questions_id, answer, user_id, is_correct, created_at) FROM stdin;
    public          postgres    false    213   �       P           0    0    responses_responses_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('public.responses_responses_id_seq', 100, true);
          public          postgres    false    212            �
           2606    116419    responses responses_pkey 
   CONSTRAINT     `   ALTER TABLE ONLY public.responses
    ADD CONSTRAINT responses_pkey PRIMARY KEY (responses_id);
 B   ALTER TABLE ONLY public.responses DROP CONSTRAINT responses_pkey;
       public            postgres    false    213            �
           2606    116420    responses fk_questions_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.responses
    ADD CONSTRAINT fk_questions_id FOREIGN KEY (questions_id) REFERENCES public.questions(questions_id);
 C   ALTER TABLE ONLY public.responses DROP CONSTRAINT fk_questions_id;
       public          postgres    false    213            �
           2606    116425    responses fk_userids    FK CONSTRAINT     x   ALTER TABLE ONLY public.responses
    ADD CONSTRAINT fk_userids FOREIGN KEY (user_id) REFERENCES public.users(user_id);
 >   ALTER TABLE ONLY public.responses DROP CONSTRAINT fk_userids;
       public          postgres    false    213            H   �  x�}�K��:E��*jm�O�ky㷂�?�*�R��3�{IJorӛ���MY���/�S��>x�E���I��Bi�;ZE������1mYI�Q��w*�G�#U3%��H�P��GPrF�YM=�P�i�ֳ���}���DY+i��@�ʤ�=�zv���@��[��ԡ�I&K�9����wjc�U��l�zTr�r0����\Y �O(�K��Ԟu�j��`�=�j�2*�J����"[���R6o���ۖ��9�U"�*�\2�Qf��W��D��v9|ֲ���ˏlu�G�g�>��\�)Cd��~U=8�m�H۽�{r�fģ��U�ʎ��Tg��m��+{
����..��:�������&�'C�|Tu�P�Sz�C�Ma�tܸϜ樤��-�ò�7�5G|��rJl�l��f����p��"�4l�n���I��k�C)Ʀ,6�lrKhP����0MJ��z�jv��$��aØY(mb�kZ�.Q���`���O�{L��!��Ӛ%���H��u
�d��e]}u:�����%�zZ���(Vx��`�j�3�x4ս��
�1�����ɼ����`ؾF���?�}�0W զ�����t���97��pm���N�n���� �� �¦�v5�~�-6�ȱ�9�����TԲ�o�����ܺ����Զ�f3��@����t�c���U'��pK��D0a$Z�%��Ӿ>��P����A6�I�t=V���͕�G����E��0���Q2�1�s�����4t�V���19��륺6����8J!��E���IśsX�X��	+�G��U���ƅ��,I��<jU�'h{�������C3��_.�0(.�����ww^�l��w�?Z)�     